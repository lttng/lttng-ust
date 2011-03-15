/*
 * tracer.c
 *
 * (C) Copyright	2005-2008 -
 * 		Mathieu Desnoyers (mathieu.desnoyers@polymtl.ca)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 *
 * Inspired from LTT :
 *  Karim Yaghmour (karim@opersys.com)
 *  Tom Zanussi (zanussi@us.ibm.com)
 *  Bob Wisniewski (bob@watson.ibm.com)
 * And from K42 :
 *  Bob Wisniewski (bob@watson.ibm.com)
 *
 * Changelog:
 *  22/09/06, Move to the marker/probes mechanism.
 *  19/10/05, Complete lockless mechanism.
 *  27/05/05, Modular redesign and rewrite.
 */

#include <urcu-bp.h>
#include <urcu/rculist.h>

#include <ust/clock.h>

#include "tracercore.h"
#include "tracer.h"
#include "usterr.h"

struct chan_info_struct chan_infos[] = {
	[LTT_CHANNEL_METADATA] = {
		LTT_METADATA_CHANNEL,
		LTT_DEFAULT_SUBBUF_SIZE_LOW,
		LTT_DEFAULT_N_SUBBUFS_LOW,
	},
	[LTT_CHANNEL_UST] = {
		LTT_UST_CHANNEL,
		LTT_DEFAULT_SUBBUF_SIZE_HIGH,
		LTT_DEFAULT_N_SUBBUFS_HIGH,
	},
};

static enum ltt_channels get_channel_type_from_name(const char *name)
{
	int i;

	if (!name)
		return LTT_CHANNEL_UST;

	for (i = 0; i < ARRAY_SIZE(chan_infos); i++)
		if (chan_infos[i].name && !strcmp(name, chan_infos[i].name))
			return (enum ltt_channels)i;

	return LTT_CHANNEL_UST;
}

static CDS_LIST_HEAD(ltt_transport_list);
/* transport mutex, nests inside traces mutex (ltt_lock_traces) */
static DEFINE_MUTEX(ltt_transport_mutex);
/**
 * ltt_transport_register - LTT transport registration
 * @transport: transport structure
 *
 * Registers a transport which can be used as output to extract the data out of
 * LTTng. The module calling this registration function must ensure that no
 * trap-inducing code will be executed by the transport functions. E.g.
 * vmalloc_sync_all() must be called between a vmalloc and the moment the memory
 * is made visible to the transport function. This registration acts as a
 * vmalloc_sync_all. Therefore, only if the module allocates virtual memory
 * after its registration must it synchronize the TLBs.
 */
void ltt_transport_register(struct ltt_transport *transport)
{
	pthread_mutex_lock(&ltt_transport_mutex);
	cds_list_add_tail(&transport->node, &ltt_transport_list);
	pthread_mutex_unlock(&ltt_transport_mutex);
}

/**
 * ltt_transport_unregister - LTT transport unregistration
 * @transport: transport structure
 */
void ltt_transport_unregister(struct ltt_transport *transport)
{
	pthread_mutex_lock(&ltt_transport_mutex);
	cds_list_del(&transport->node);
	pthread_mutex_unlock(&ltt_transport_mutex);
}

static inline int is_channel_overwrite(enum ltt_channels chan,
	enum trace_mode mode)
{
	switch (mode) {
	case LTT_TRACE_NORMAL:
		return 0;
	case LTT_TRACE_FLIGHT:
		switch (chan) {
		case LTT_CHANNEL_METADATA:
			return 0;
		default:
			return 1;
		}
	case LTT_TRACE_HYBRID:
		switch (chan) {
		case LTT_CHANNEL_METADATA:
			return 0;
		default:
			return 1;
		}
	default:
		return 0;
	}
}

static void trace_async_wakeup(struct ust_trace *trace)
{
	int i;
	struct ust_channel *chan;

	/* Must check each channel for pending read wakeup */
	for (i = 0; i < trace->nr_channels; i++) {
		chan = &trace->channels[i];
		if (chan->active)
			trace->ops->wakeup_channel(chan);
	}
}

/**
 * _ltt_trace_find - find a trace by given name.
 * trace_name: trace name
 *
 * Returns a pointer to the trace structure, NULL if not found.
 */
struct ust_trace *_ltt_trace_find(const char *trace_name)
{
	struct ust_trace *trace;

	cds_list_for_each_entry(trace, &ltt_traces.head, list)
		if (!strncmp(trace->trace_name, trace_name, NAME_MAX))
			return trace;

	return NULL;
}

/* _ltt_trace_find_setup :
 * find a trace in setup list by given name.
 *
 * Returns a pointer to the trace structure, NULL if not found.
 */
struct ust_trace *_ltt_trace_find_setup(const char *trace_name)
{
	struct ust_trace *trace;

	cds_list_for_each_entry(trace, &ltt_traces.setup_head, list)
		if (!strncmp(trace->trace_name, trace_name, NAME_MAX))
			return trace;

	return NULL;
}

/**
 * ltt_release_transport - Release an LTT transport
 * @kref : reference count on the transport
 */
void ltt_release_transport(struct urcu_ref *urcu_ref)
{
	return;
}

/**
 * ltt_release_trace - Release a LTT trace
 * @kref : reference count on the trace
 */
void ltt_release_trace(struct urcu_ref *urcu_ref)
{
	struct ust_trace *trace = _ust_container_of(urcu_ref,
			struct ust_trace, urcu_ref);
	ltt_channels_trace_free(trace->channels);
	free(trace);
}

static inline void prepare_chan_size_num(unsigned int *subbuf_size,
					 unsigned int *n_subbufs)
{
	/* Make sure the subbuffer size is larger than a page */
	*subbuf_size = max_t(unsigned int, *subbuf_size, PAGE_SIZE);

	/* round to next power of 2 */
	*subbuf_size = 1 << get_count_order(*subbuf_size);
	*n_subbufs = 1 << get_count_order(*n_subbufs);

	/* Subbuf size and number must both be power of two */
	WARN_ON(hweight32(*subbuf_size) != 1);
	WARN_ON(hweight32(*n_subbufs) != 1);
}

int _ltt_trace_setup(const char *trace_name)
{
	int err = 0;
	struct ust_trace *new_trace = NULL;
	int metadata_index;
	unsigned int chan;
	enum ltt_channels chantype;

	if (_ltt_trace_find_setup(trace_name)) {
		ERR("Trace name %s already used", trace_name);
		err = -EEXIST;
		goto traces_error;
	}

	if (_ltt_trace_find(trace_name)) {
		ERR("Trace name %s already used", trace_name);
		err = -EEXIST;
		goto traces_error;
	}

	new_trace = zmalloc(sizeof(struct ust_trace));
	if (!new_trace) {
		ERR("Unable to allocate memory for trace %s", trace_name);
		err = -ENOMEM;
		goto traces_error;
	}
	strncpy(new_trace->trace_name, trace_name, NAME_MAX);
	new_trace->channels = ltt_channels_trace_alloc(&new_trace->nr_channels,
				ust_channels_overwrite_by_default,
				ust_channels_request_collection_by_default, 1);
	if (!new_trace->channels) {
		ERR("Unable to allocate memory for chaninfo  %s\n", trace_name);
		err = -ENOMEM;
		goto trace_free;
	}

	/*
	 * Force metadata channel to active, no overwrite.
	 */
	metadata_index = ltt_channels_get_index_from_name("metadata");
	WARN_ON(metadata_index < 0);
	new_trace->channels[metadata_index].overwrite = 0;
	new_trace->channels[metadata_index].active = 1;

	/*
	 * Set hardcoded tracer defaults for some channels
	 */
	for (chan = 0; chan < new_trace->nr_channels; chan++) {
		if (!(new_trace->channels[chan].active))
			continue;

		chantype = get_channel_type_from_name(
			ltt_channels_get_name_from_index(chan));
		new_trace->channels[chan].subbuf_size =
			chan_infos[chantype].def_subbufsize;
		new_trace->channels[chan].subbuf_cnt =
			chan_infos[chantype].def_subbufcount;
	}

	cds_list_add(&new_trace->list, &ltt_traces.setup_head);
	return 0;

trace_free:
	free(new_trace);
traces_error:
	return err;
}


int ltt_trace_setup(const char *trace_name)
{
	int ret;
	ltt_lock_traces();
	ret = _ltt_trace_setup(trace_name);
	ltt_unlock_traces();
	return ret;
}

/* must be called from within a traces lock. */
static void _ltt_trace_free(struct ust_trace *trace)
{
	cds_list_del(&trace->list);
	free(trace);
}

int ltt_trace_set_type(const char *trace_name, const char *trace_type)
{
	int err = 0;
	struct ust_trace *trace;
	struct ltt_transport *tran_iter, *transport = NULL;

	ltt_lock_traces();

	trace = _ltt_trace_find_setup(trace_name);
	if (!trace) {
		ERR("Trace not found %s", trace_name);
		err = -ENOENT;
		goto traces_error;
	}

	pthread_mutex_lock(&ltt_transport_mutex);
	cds_list_for_each_entry(tran_iter, &ltt_transport_list, node) {
		if (!strcmp(tran_iter->name, trace_type)) {
			transport = tran_iter;
			break;
		}
	}
	pthread_mutex_unlock(&ltt_transport_mutex);

	if (!transport) {
		ERR("Transport %s is not present", trace_type);
		err = -EINVAL;
		goto traces_error;
	}

	trace->transport = transport;

traces_error:
	ltt_unlock_traces();
	return err;
}

int ltt_trace_set_channel_subbufsize(const char *trace_name,
		const char *channel_name, unsigned int size)
{
	int err = 0;
	struct ust_trace *trace;
	int index;

	ltt_lock_traces();

	trace = _ltt_trace_find_setup(trace_name);
	if (!trace) {
		ERR("Trace not found %s", trace_name);
		err = -ENOENT;
		goto traces_error;
	}

	index = ltt_channels_get_index_from_name(channel_name);
	if (index < 0) {
		ERR("Channel %s not found", channel_name);
		err = -ENOENT;
		goto traces_error;
	}
	trace->channels[index].subbuf_size = size;

traces_error:
	ltt_unlock_traces();
	return err;
}

int ltt_trace_set_channel_subbufcount(const char *trace_name,
		const char *channel_name, unsigned int cnt)
{
	int err = 0;
	struct ust_trace *trace;
	int index;

	ltt_lock_traces();

	trace = _ltt_trace_find_setup(trace_name);
	if (!trace) {
		ERR("Trace not found %s", trace_name);
		err = -ENOENT;
		goto traces_error;
	}

	index = ltt_channels_get_index_from_name(channel_name);
	if (index < 0) {
		ERR("Channel %s not found", channel_name);
		err = -ENOENT;
		goto traces_error;
	}
	trace->channels[index].subbuf_cnt = cnt;

traces_error:
	ltt_unlock_traces();
	return err;
}

int ltt_trace_set_channel_enable(const char *trace_name,
		const char *channel_name, unsigned int enable)
{
	int err = 0;
	struct ust_trace *trace;
	int index;

	ltt_lock_traces();

	trace = _ltt_trace_find_setup(trace_name);
	if (!trace) {
		ERR("Trace not found %s", trace_name);
		err = -ENOENT;
		goto traces_error;
	}

	/*
	 * Datas in metadata channel(marker info) is necessary to be able to
	 * read the trace, we always enable this channel.
	 */
	if (!enable && !strcmp(channel_name, "metadata")) {
		ERR("Trying to disable metadata channel");
		err = -EINVAL;
		goto traces_error;
	}

	index = ltt_channels_get_index_from_name(channel_name);
	if (index < 0) {
		ERR("Channel %s not found", channel_name);
		err = -ENOENT;
		goto traces_error;
	}

	trace->channels[index].active = enable;

traces_error:
	ltt_unlock_traces();
	return err;
}

int ltt_trace_set_channel_overwrite(const char *trace_name,
		const char *channel_name, unsigned int overwrite)
{
	int err = 0;
	struct ust_trace *trace;
	int index;

	ltt_lock_traces();

	trace = _ltt_trace_find_setup(trace_name);
	if (!trace) {
		ERR("Trace not found %s", trace_name);
		err = -ENOENT;
		goto traces_error;
	}

	/*
	 * Always put the metadata channel in non-overwrite mode :
	 * This is a very low traffic channel and it can't afford to have its
	 * data overwritten : this data (marker info) is necessary to be
	 * able to read the trace.
	 */
	if (overwrite && !strcmp(channel_name, "metadata")) {
		ERR("Trying to set metadata channel to overwrite mode");
		err = -EINVAL;
		goto traces_error;
	}

	index = ltt_channels_get_index_from_name(channel_name);
	if (index < 0) {
		ERR("Channel %s not found", channel_name);
		err = -ENOENT;
		goto traces_error;
	}

	trace->channels[index].overwrite = overwrite;

traces_error:
	ltt_unlock_traces();
	return err;
}

int ltt_trace_alloc(const char *trace_name)
{
	int err = 0;
	struct ust_trace *trace;
	unsigned int subbuf_size, subbuf_cnt;
	int chan;
	const char *channel_name;

	ltt_lock_traces();

	if (_ltt_trace_find(trace_name)) { /* Trace already allocated */
		err = 1;
		goto traces_error;
	}

	trace = _ltt_trace_find_setup(trace_name);
	if (!trace) {
		ERR("Trace not found %s", trace_name);
		err = -ENOENT;
		goto traces_error;
	}

	urcu_ref_init(&trace->urcu_ref);
	urcu_ref_init(&trace->ltt_transport_urcu_ref);
	trace->active = 0;
	trace->freq_scale = trace_clock_freq_scale();

	if (!trace->transport) {
		ERR("Transport is not set");
		err = -EINVAL;
		goto transport_error;
	}
	trace->ops = &trace->transport->ops;

	trace->start_freq = trace_clock_frequency();
	trace->start_tsc = trace_clock_read64();
	gettimeofday(&trace->start_time, NULL); //ust// changed /* FIXME: is this ok? */

	for (chan = 0; chan < trace->nr_channels; chan++) {
		if (!(trace->channels[chan].active))
			continue;

		channel_name = ltt_channels_get_name_from_index(chan);
		WARN_ON(!channel_name);
		subbuf_size = trace->channels[chan].subbuf_size;
		subbuf_cnt = trace->channels[chan].subbuf_cnt;
		prepare_chan_size_num(&subbuf_size, &subbuf_cnt);
		err = trace->ops->create_channel(trace_name, trace,
				channel_name,
				&trace->channels[chan],
				subbuf_size,
				subbuf_cnt,
				trace->channels[chan].overwrite);
		if (err != 0) {
			ERR("Cannot create channel %s", channel_name);
			goto create_channel_error;
		}
	}

	cds_list_del(&trace->list);
	cds_list_add_rcu(&trace->list, &ltt_traces.head);

	ltt_unlock_traces();

	return 0;

create_channel_error:
	for (chan--; chan >= 0; chan--)
		if (trace->channels[chan].active)
			trace->ops->remove_channel(&trace->channels[chan]);

transport_error:
traces_error:
	ltt_unlock_traces();
	return err;
}

/* Must be called while sure that trace is in the list. */
static int _ltt_trace_destroy(struct ust_trace *trace)
{
	int err = -EPERM;

	if (trace == NULL) {
		err = -ENOENT;
		goto traces_error;
	}
	if (trace->active) {
		ERR("Can't destroy trace %s : tracer is active", trace->trace_name);
		err = -EBUSY;
		goto active_error;
	}

	cds_list_del_rcu(&trace->list);
	synchronize_rcu();

	return 0;

active_error:
traces_error:
	return err;
}

/* Sleepable part of the destroy */
static void __ltt_trace_destroy(struct ust_trace *trace, int drop)
{
	int i;
	struct ust_channel *chan;

	if(!drop) {
		for (i = 0; i < trace->nr_channels; i++) {
			chan = &trace->channels[i];
			if (chan->active)
				trace->ops->finish_channel(chan);
		}
	}

	/*
	 * The currently destroyed trace is not in the trace list anymore,
	 * so it's safe to call the async wakeup ourself. It will deliver
	 * the last subbuffers.
	 */
	trace_async_wakeup(trace);

	for (i = 0; i < trace->nr_channels; i++) {
		chan = &trace->channels[i];
		if (chan->active)
			trace->ops->remove_channel(chan);
	}

	urcu_ref_put(&trace->ltt_transport_urcu_ref, ltt_release_transport);

	urcu_ref_put(&trace->urcu_ref, ltt_release_trace);
}

int ltt_trace_destroy(const char *trace_name, int drop)
{
	int err = 0;
	struct ust_trace *trace;

	ltt_lock_traces();

	trace = _ltt_trace_find(trace_name);
	if (trace) {
		err = _ltt_trace_destroy(trace);
		if (err)
			goto error;

		ltt_unlock_traces();

		__ltt_trace_destroy(trace, drop);

		return 0;
	}

	trace = _ltt_trace_find_setup(trace_name);
	if (trace) {
		_ltt_trace_free(trace);
		ltt_unlock_traces();
		return 0;
	}

	err = -ENOENT;

error:
	ltt_unlock_traces();
	return err;
}

/* must be called from within a traces lock. */
static int _ltt_trace_start(struct ust_trace *trace)
{
	int err = 0;

	if (trace == NULL) {
		err = -ENOENT;
		goto traces_error;
	}
	if (trace->active)
		DBG("Tracing already active for trace %s", trace->trace_name);
	trace->active = 1;
	/* Read by trace points without protection : be careful */
	ltt_traces.num_active_traces++;
	return err;

traces_error:
	return err;
}

int ltt_trace_start(const char *trace_name)
{
	int err = 0;
	struct ust_trace *trace;

	ltt_lock_traces();

	trace = _ltt_trace_find(trace_name);
	err = _ltt_trace_start(trace);
	if (err)
		goto no_trace;

	ltt_unlock_traces();

	/*
	 * Call the process-wide state dump.
	 * Notice that there is no protection on the trace : that's exactly
	 * why we iterate on the list and check for trace equality instead of
	 * directly using this trace handle inside the logging function: we want
	 * to record events only in a single trace in the trace session list.
	 */

	ltt_dump_marker_state(trace);

	return err;

	/* Error handling */
no_trace:
	ltt_unlock_traces();
	return err;
}

/* must be called from within traces lock */
static int _ltt_trace_stop(struct ust_trace *trace)
{
	int err = -EPERM;

	if (trace == NULL) {
		err = -ENOENT;
		goto traces_error;
	}
	if (!trace->active)
		DBG("LTT : Tracing not active for trace %s", trace->trace_name);
	if (trace->active) {
		trace->active = 0;
		ltt_traces.num_active_traces--;
	}
	return 0;

traces_error:
	return err;
}

int ltt_trace_stop(const char *trace_name)
{
	int err = 0;
	struct ust_trace *trace;

	ltt_lock_traces();
	trace = _ltt_trace_find(trace_name);
	err = _ltt_trace_stop(trace);
	ltt_unlock_traces();
	return err;
}
