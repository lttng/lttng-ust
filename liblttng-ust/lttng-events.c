/*
 * lttng-events.c
 *
 * Holds LTTng per-session event registry.
 *
 * Copyright (C) 2010-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; only
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <urcu/list.h>
#include <urcu/hlist.h>
#include <pthread.h>
#include <errno.h>
#include <sys/shm.h>
#include <sys/ipc.h>
#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>
#include <time.h>
#include <lttng/ust-endian.h>
#include "clock.h"

#include <urcu-bp.h>
#include <urcu/compiler.h>
#include <urcu/uatomic.h>
#include <urcu/arch.h>

#include <lttng/tracepoint.h>
#include <lttng/ust-events.h>

#include <usterr-signal-safe.h>
#include <helper.h>
#include <ust-ctl.h>
#include <ust-comm.h>
#include "error.h"
#include "compat.h"
#include "lttng-ust-uuid.h"

#include "tracepoint-internal.h"
#include "lttng-tracer.h"
#include "lttng-tracer-core.h"
#include "wait.h"
#include "../libringbuffer/shm.h"
#include "jhash.h"

/*
 * The sessions mutex is the centralized mutex across UST tracing
 * control and probe registration. All operations within this file are
 * called by the communication thread, under ust_lock protection.
 */
static pthread_mutex_t sessions_mutex = PTHREAD_MUTEX_INITIALIZER;

void ust_lock(void)
{
	pthread_mutex_lock(&sessions_mutex);
}

void ust_unlock(void)
{
	pthread_mutex_unlock(&sessions_mutex);
}

static CDS_LIST_HEAD(sessions);

static void _lttng_event_destroy(struct lttng_event *event);
static int _lttng_event_unregister(struct lttng_event *event);
static
int _lttng_event_metadata_statedump(struct lttng_session *session,
				  struct lttng_channel *chan,
				  struct lttng_event *event);
static
int _lttng_session_metadata_statedump(struct lttng_session *session);

static
void lttng_session_lazy_sync_enablers(struct lttng_session *session);
static
void lttng_session_sync_enablers(struct lttng_session *session);
static
void lttng_enabler_destroy(struct lttng_enabler *enabler);

/*
 * Called with ust lock held.
 */
int lttng_session_active(void)
{
	struct lttng_session *iter;

	cds_list_for_each_entry(iter, &sessions, node) {
		if (iter->active)
			return 1;
	}
	return 0;
}

static
int lttng_loglevel_match(int loglevel,
		unsigned int has_loglevel,
		enum lttng_ust_loglevel_type req_type,
		int req_loglevel)
{
	if (req_type == LTTNG_UST_LOGLEVEL_ALL)
		return 1;
	if (!has_loglevel)
		loglevel = TRACE_DEFAULT;
	switch (req_type) {
	case LTTNG_UST_LOGLEVEL_RANGE:
		if (loglevel <= req_loglevel || req_loglevel == -1)
			return 1;
		else
			return 0;
	case LTTNG_UST_LOGLEVEL_SINGLE:
		if (loglevel == req_loglevel || req_loglevel == -1)
			return 1;
		else
			return 0;
	case LTTNG_UST_LOGLEVEL_ALL:
	default:
		return 1;
	}
}

void synchronize_trace(void)
{
	synchronize_rcu();
}

struct lttng_session *lttng_session_create(void)
{
	struct lttng_session *session;
	int i;

	session = zmalloc(sizeof(struct lttng_session));
	if (!session)
		return NULL;
	CDS_INIT_LIST_HEAD(&session->chan_head);
	CDS_INIT_LIST_HEAD(&session->events_head);
	CDS_INIT_LIST_HEAD(&session->enablers_head);
	for (i = 0; i < LTTNG_UST_EVENT_HT_SIZE; i++)
		CDS_INIT_HLIST_HEAD(&session->events_ht.table[i]);
	cds_list_add(&session->node, &sessions);
	return session;
}

/*
 * Only used internally at session destruction.
 */
static
void _lttng_channel_unmap(struct lttng_channel *lttng_chan)
{
	struct channel *chan;
	struct lttng_ust_shm_handle *handle;

	cds_list_del(&lttng_chan->node);
	lttng_destroy_context(lttng_chan->ctx);
	chan = lttng_chan->chan;
	handle = lttng_chan->handle;
	/*
	 * note: lttng_chan is private data contained within handle. It
	 * will be freed along with the handle.
	 */
	channel_destroy(chan, handle, 0);
}

void lttng_session_destroy(struct lttng_session *session)
{
	struct lttng_channel *chan, *tmpchan;
	struct lttng_event *event, *tmpevent;
	struct lttng_enabler *enabler, *tmpenabler;
	int ret;

	CMM_ACCESS_ONCE(session->active) = 0;
	cds_list_for_each_entry(event, &session->events_head, node) {
		ret = _lttng_event_unregister(event);
		WARN_ON(ret);
	}
	synchronize_trace();	/* Wait for in-flight events to complete */
	cds_list_for_each_entry_safe(enabler, tmpenabler,
			&session->enablers_head, node)
		lttng_enabler_destroy(enabler);
	cds_list_for_each_entry_safe(event, tmpevent,
			&session->events_head, node)
		_lttng_event_destroy(event);
	cds_list_for_each_entry_safe(chan, tmpchan, &session->chan_head, node)
		_lttng_channel_unmap(chan);
	cds_list_del(&session->node);
	free(session);
}

int lttng_session_enable(struct lttng_session *session)
{
	int ret = 0;
	struct lttng_channel *chan;
	int notify_socket;

	if (session->active) {
		ret = -EBUSY;
		goto end;
	}

	notify_socket = lttng_get_notify_socket(session->owner);
	if (notify_socket < 0)
		return notify_socket;

	/* We need to sync enablers with session before activation. */
	lttng_session_sync_enablers(session);

	/*
	 * Snapshot the number of events per channel to know the type of header
	 * we need to use.
	 */
	cds_list_for_each_entry(chan, &session->chan_head, node) {
		const struct lttng_ctx *ctx;
		const struct lttng_event_field *fields = NULL;
		size_t nr_fields = 0;

		/* don't change it if session stop/restart */
		if (chan->header_type)
			continue;
		ctx = chan->ctx;
		if (ctx) {
			nr_fields = ctx->nr_fields;
			fields = &ctx->fields->event_field;
		}
		ret = ustcomm_register_channel(notify_socket,
			session->objd,
			chan->objd,
			nr_fields,
			fields,
			&chan->id,
			&chan->header_type);
		if (ret)
			return ret;
	}

	CMM_ACCESS_ONCE(session->active) = 1;
	CMM_ACCESS_ONCE(session->been_active) = 1;
end:
	return ret;
}

int lttng_session_disable(struct lttng_session *session)
{
	int ret = 0;

	if (!session->active) {
		ret = -EBUSY;
		goto end;
	}
	CMM_ACCESS_ONCE(session->active) = 0;
end:
	return ret;
}

int lttng_channel_enable(struct lttng_channel *channel)
{
	int old;

	if (channel == channel->session->metadata)
		return -EPERM;
	old = uatomic_xchg(&channel->enabled, 1);
	if (old)
		return -EEXIST;
	return 0;
}

int lttng_channel_disable(struct lttng_channel *channel)
{
	int old;

	if (channel == channel->session->metadata)
		return -EPERM;
	old = uatomic_xchg(&channel->enabled, 0);
	if (!old)
		return -EEXIST;
	return 0;
}

int lttng_event_enable(struct lttng_event *event)
{
	int old;

	if (event->chan == event->chan->session->metadata)
		return -EPERM;
	old = uatomic_xchg(&event->enabled, 1);
	if (old)
		return -EEXIST;
	return 0;
}

int lttng_event_disable(struct lttng_event *event)
{
	int old;

	if (event->chan == event->chan->session->metadata)
		return -EPERM;
	old = uatomic_xchg(&event->enabled, 0);
	if (!old)
		return -EEXIST;
	return 0;
}

/*
 * Supports event creation while tracing session is active.
 */
static
int lttng_event_create(const struct lttng_event_desc *desc,
		struct lttng_channel *chan)
{
	const char *event_name = desc->name;
	struct lttng_event *event;
	struct lttng_session *session = chan->session;
	struct cds_hlist_head *head;
	struct cds_hlist_node *node;
	int ret = 0;
	size_t name_len = strlen(event_name);
	uint32_t hash;
	int notify_socket, loglevel;
	const char *uri;

	hash = jhash(event_name, name_len, 0);
	head = &chan->session->events_ht.table[hash & (LTTNG_UST_EVENT_HT_SIZE - 1)];
	cds_hlist_for_each_entry(event, node, head, hlist) {
		assert(event->desc);
		if (!strncmp(event->desc->name,
				desc->name,
				LTTNG_UST_SYM_NAME_LEN - 1)) {
			ret = -EEXIST;
			goto exist;
		}
	}

	notify_socket = lttng_get_notify_socket(session->owner);
	if (notify_socket < 0) {
		ret = notify_socket;
		goto socket_error;
	}

	/*
	 * Check if loglevel match. Refuse to connect event if not.
	 */
	event = zmalloc(sizeof(struct lttng_event));
	if (!event) {
		ret = -ENOMEM;
		goto cache_error;
	}
	event->chan = chan;

	event->enabled = 1;
	CDS_INIT_LIST_HEAD(&event->bytecode_runtime_head);
	CDS_INIT_LIST_HEAD(&event->enablers_ref_head);
	event->desc = desc;

	if (desc->loglevel)
		loglevel = *(*event->desc->loglevel);
	else
		loglevel = TRACE_DEFAULT;
	if (desc->u.ext.model_emf_uri)
		uri = *(desc->u.ext.model_emf_uri);
	else
		uri = NULL;

	/* Don't register metadata events */
	if (session->metadata == chan) {
		event->id = -1U;
	} else {
		/* Fetch event ID from sessiond */
		ret = ustcomm_register_event(notify_socket,
			session->objd,
			chan->objd,
			event_name,
			loglevel,
			desc->signature,
			desc->nr_fields,
			desc->fields,
			uri,
			&event->id);
		if (ret < 0) {
			goto sessiond_register_error;
		}
	}

	/* Populate lttng_event structure before tracepoint registration. */
	cmm_smp_wmb();
	ret = __tracepoint_probe_register(event_name,
			desc->probe_callback,
			event, desc->signature);
	if (ret)
		goto tracepoint_register_error;

	cds_list_add(&event->node, &chan->session->events_head);
	cds_hlist_add_head(&event->hlist, head);
	return 0;

tracepoint_register_error:
sessiond_register_error:
	free(event);
cache_error:
socket_error:
exist:
	return ret;
}

static
int lttng_desc_match_wildcard_enabler(const struct lttng_event_desc *desc,
		struct lttng_enabler *enabler)
{
	int loglevel = 0;
	unsigned int has_loglevel;

	assert(enabler->type == LTTNG_ENABLER_WILDCARD);
	/* Compare excluding final '*' */
	if (strncmp(desc->name, enabler->event_param.name,
			strlen(enabler->event_param.name) - 1))
		return 0;
	if (desc->loglevel) {
		loglevel = *(*desc->loglevel);
		has_loglevel = 1;
	}
	if (!lttng_loglevel_match(loglevel,
			has_loglevel,
			enabler->event_param.loglevel_type,
			enabler->event_param.loglevel))
		return 0;
	return 1;
}

static
int lttng_desc_match_event_enabler(const struct lttng_event_desc *desc,
		struct lttng_enabler *enabler)
{
	int loglevel = 0;
	unsigned int has_loglevel = 0;

	assert(enabler->type == LTTNG_ENABLER_EVENT);
	if (strcmp(desc->name, enabler->event_param.name))
		return 0;
	if (desc->loglevel) {
		loglevel = *(*desc->loglevel);
		has_loglevel = 1;
	}
	if (!lttng_loglevel_match(loglevel,
			has_loglevel,
			enabler->event_param.loglevel_type,
			enabler->event_param.loglevel))
		return 0;
	return 1;
}

static
int lttng_desc_match_enabler(const struct lttng_event_desc *desc,
		struct lttng_enabler *enabler)
{
	switch (enabler->type) {
	case LTTNG_ENABLER_WILDCARD:
		return lttng_desc_match_wildcard_enabler(desc, enabler);
	case LTTNG_ENABLER_EVENT:
		return lttng_desc_match_event_enabler(desc, enabler);
	default:
		return -EINVAL;
	}
}

static
int lttng_event_match_enabler(struct lttng_event *event,
		struct lttng_enabler *enabler)
{
	return lttng_desc_match_enabler(event->desc, enabler);
}

static
struct lttng_enabler_ref * lttng_event_enabler_ref(struct lttng_event *event,
		struct lttng_enabler *enabler)
{
	struct lttng_enabler_ref *enabler_ref;

	cds_list_for_each_entry(enabler_ref,
			&event->enablers_ref_head, node) {
		if (enabler_ref->ref == enabler)
			return enabler_ref;
	}
	return NULL;
}

/*
 * Create struct lttng_event if it is missing and present in the list of
 * tracepoint probes.
 */
static
void lttng_create_event_if_missing(struct lttng_enabler *enabler)
{
	struct lttng_session *session = enabler->chan->session;
	struct lttng_probe_desc *probe_desc;
	const struct lttng_event_desc *desc;
	struct lttng_event *event;
	int i;
	struct cds_list_head *probe_list;

	probe_list = lttng_get_probe_list_head();
	/*
	 * For each probe event, if we find that a probe event matches
	 * our enabler, create an associated lttng_event if not
	 * already present.
	 */
	cds_list_for_each_entry(probe_desc, probe_list, head) {
		for (i = 0; i < probe_desc->nr_events; i++) {
			int found = 0, ret;
			struct cds_hlist_head *head;
			struct cds_hlist_node *node;
			const char *event_name;
			size_t name_len;
			uint32_t hash;

			desc = probe_desc->event_desc[i];
			if (!lttng_desc_match_enabler(desc, enabler))
				continue;
			event_name = desc->name;
			name_len = strlen(event_name);

			/*
			 * Check if already created.
			 */
			hash = jhash(event_name, name_len, 0);
			head = &session->events_ht.table[hash & (LTTNG_UST_EVENT_HT_SIZE - 1)];
			cds_hlist_for_each_entry(event, node, head, hlist) {
				if (event->desc == desc)
					found = 1;
			}
			if (found)
				continue;

			/*
			 * We need to create an event for this
			 * event probe.
			 */
			ret = lttng_event_create(probe_desc->event_desc[i],
					enabler->chan);
			if (ret) {
				DBG("Unable to create event %s, error %d\n",
					probe_desc->event_desc[i]->name, ret);
			}
		}
	}
}

/*
 * Create events associated with an enabler (if not already present),
 * and add backward reference from the event to the enabler.
 */
static
int lttng_enabler_ref_events(struct lttng_enabler *enabler)
{
	struct lttng_session *session = enabler->chan->session;
	struct lttng_event *event;

	/* First ensure that probe events are created for this enabler. */
	lttng_create_event_if_missing(enabler);

	/* For each event matching enabler in session event list. */
	cds_list_for_each_entry(event, &session->events_head, node) {
		struct lttng_enabler_ref *enabler_ref;

		if (!lttng_event_match_enabler(event, enabler))
			continue;

		enabler_ref = lttng_event_enabler_ref(event, enabler);
		if (!enabler_ref) {
			/*
			 * If no backward ref, create it.
			 * Add backward ref from event to enabler.
			 */
			enabler_ref = zmalloc(sizeof(*enabler_ref));
			if (!enabler_ref)
				return -ENOMEM;
			enabler_ref->ref = enabler;
			cds_list_add(&enabler_ref->node,
				&event->enablers_ref_head);
		}

		/*
		 * Link filter bytecodes if not linked yet.
		 */
		lttng_enabler_event_link_bytecode(event, enabler);

		/* TODO: merge event context. */
	}
	return 0;
}

/*
 * Called at library load: connect the probe on all enablers matching
 * this event.
 * called with session mutex held.
 * TODO: currently, for each desc added, we iterate on all event desc
 * (inefficient). We should create specific code that only target the
 * added desc.
 */
int lttng_fix_pending_event_desc(const struct lttng_event_desc *desc)
{
	struct lttng_session *session;

	cds_list_for_each_entry(session, &sessions, node) {
		lttng_session_lazy_sync_enablers(session);
	}
	return 0;
}

/*
 * Only used internally at session destruction.
 */
int _lttng_event_unregister(struct lttng_event *event)
{
	return __tracepoint_probe_unregister(event->desc->name,
					  event->desc->probe_callback,
					  event);
}

/*
 * Only used internally at session destruction.
 */
static
void _lttng_event_destroy(struct lttng_event *event)
{
	struct lttng_enabler_ref *enabler_ref, *tmp_enabler_ref;

	cds_list_del(&event->node);
	lttng_destroy_context(event->ctx);
	lttng_free_event_filter_runtime(event);
	/* Free event enabler refs */
	cds_list_for_each_entry_safe(enabler_ref, tmp_enabler_ref,
			&event->enablers_ref_head, node)
		free(enabler_ref);
	free(event);
}

/*
 * We have exclusive access to our metadata buffer (protected by the
 * ust_lock), so we can do racy operations such as looking for
 * remaining space left in packet and write, since mutual exclusion
 * protects us from concurrent writes.
 */
int lttng_metadata_printf(struct lttng_session *session,
			  const char *fmt, ...)
{
	struct lttng_ust_lib_ring_buffer_ctx ctx;
	struct lttng_channel *chan = session->metadata;
	char *str = NULL;
	int ret = 0, waitret;
	size_t len, reserve_len, pos;
	va_list ap;

	WARN_ON_ONCE(!CMM_ACCESS_ONCE(session->active));

	va_start(ap, fmt);
	ret = vasprintf(&str, fmt, ap);
	va_end(ap);
	if (ret < 0)
		return -ENOMEM;

	len = strlen(str);
	pos = 0;

	for (pos = 0; pos < len; pos += reserve_len) {
		reserve_len = min_t(size_t,
				chan->ops->packet_avail_size(chan->chan, chan->handle),
				len - pos);
		lib_ring_buffer_ctx_init(&ctx, chan->chan, NULL, reserve_len,
					 sizeof(char), -1, chan->handle);
		/*
		 * We don't care about metadata buffer's records lost
		 * count, because we always retry here. Report error if
		 * we need to bail out after timeout or being
		 * interrupted.
		 */
		waitret = wait_cond_interruptible_timeout(
			({
				ret = chan->ops->event_reserve(&ctx, 0);
				ret != -ENOBUFS || !ret;
			}),
			LTTNG_METADATA_TIMEOUT_MSEC);
		if (waitret == -ETIMEDOUT || waitret == -EINTR || ret) {
			DBG("LTTng: Failure to write metadata to buffers (%s)\n",
				waitret == -EINTR ? "interrupted" :
					(ret == -ENOBUFS ? "timeout" : "I/O error"));
			if (waitret == -EINTR)
				ret = waitret;
			goto end;
		}
		chan->ops->event_write(&ctx, &str[pos], reserve_len);
		chan->ops->event_commit(&ctx);
	}
end:
	free(str);
	return ret;
}

static
int _lttng_field_statedump(struct lttng_session *session,
			 const struct lttng_event_field *field)
{
	int ret = 0;

	if (field->nowrite)
		return 0;

	switch (field->type.atype) {
	case atype_integer:
		ret = lttng_metadata_printf(session,
			"		integer { size = %u; align = %u; signed = %u; encoding = %s; base = %u;%s } _%s;\n",
			field->type.u.basic.integer.size,
			field->type.u.basic.integer.alignment,
			field->type.u.basic.integer.signedness,
			(field->type.u.basic.integer.encoding == lttng_encode_none)
				? "none"
				: (field->type.u.basic.integer.encoding == lttng_encode_UTF8)
					? "UTF8"
					: "ASCII",
			field->type.u.basic.integer.base,
#if (BYTE_ORDER == BIG_ENDIAN)
			field->type.u.basic.integer.reverse_byte_order ? " byte_order = le;" : "",
#else
			field->type.u.basic.integer.reverse_byte_order ? " byte_order = be;" : "",
#endif
			field->name);
		break;
	case atype_float:
		ret = lttng_metadata_printf(session,
			"		floating_point { exp_dig = %u; mant_dig = %u; align = %u;%s } _%s;\n",
			field->type.u.basic._float.exp_dig,
			field->type.u.basic._float.mant_dig,
			field->type.u.basic._float.alignment,
#if (BYTE_ORDER == BIG_ENDIAN)
			field->type.u.basic.integer.reverse_byte_order ? " byte_order = le;" : "",
#else
			field->type.u.basic.integer.reverse_byte_order ? " byte_order = be;" : "",
#endif
			field->name);
		break;
	case atype_enum:
		ret = lttng_metadata_printf(session,
			"		%s %s;\n",
			field->type.u.basic.enumeration.name,
			field->name);
		break;
	case atype_array:
	{
		const struct lttng_basic_type *elem_type;

		elem_type = &field->type.u.array.elem_type;
		ret = lttng_metadata_printf(session,
			"		integer { size = %u; align = %u; signed = %u; encoding = %s; base = %u;%s } _%s[%u];\n",
			elem_type->u.basic.integer.size,
			elem_type->u.basic.integer.alignment,
			elem_type->u.basic.integer.signedness,
			(elem_type->u.basic.integer.encoding == lttng_encode_none)
				? "none"
				: (elem_type->u.basic.integer.encoding == lttng_encode_UTF8)
					? "UTF8"
					: "ASCII",
			elem_type->u.basic.integer.base,
#if (BYTE_ORDER == BIG_ENDIAN)
			elem_type->u.basic.integer.reverse_byte_order ? " byte_order = le;" : "",
#else
			elem_type->u.basic.integer.reverse_byte_order ? " byte_order = be;" : "",
#endif
			field->name, field->type.u.array.length);
		break;
	}
	case atype_sequence:
	{
		const struct lttng_basic_type *elem_type;
		const struct lttng_basic_type *length_type;

		elem_type = &field->type.u.sequence.elem_type;
		length_type = &field->type.u.sequence.length_type;
		ret = lttng_metadata_printf(session,
			"		integer { size = %u; align = %u; signed = %u; encoding = %s; base = %u;%s } __%s_length;\n",
			length_type->u.basic.integer.size,
			(unsigned int) length_type->u.basic.integer.alignment,
			length_type->u.basic.integer.signedness,
			(length_type->u.basic.integer.encoding == lttng_encode_none)
				? "none"
				: ((length_type->u.basic.integer.encoding == lttng_encode_UTF8)
					? "UTF8"
					: "ASCII"),
			length_type->u.basic.integer.base,
#if (BYTE_ORDER == BIG_ENDIAN)
			length_type->u.basic.integer.reverse_byte_order ? " byte_order = le;" : "",
#else
			length_type->u.basic.integer.reverse_byte_order ? " byte_order = be;" : "",
#endif
			field->name);
		if (ret)
			return ret;

		ret = lttng_metadata_printf(session,
			"		integer { size = %u; align = %u; signed = %u; encoding = %s; base = %u;%s } _%s[ __%s_length ];\n",
			elem_type->u.basic.integer.size,
			(unsigned int) elem_type->u.basic.integer.alignment,
			elem_type->u.basic.integer.signedness,
			(elem_type->u.basic.integer.encoding == lttng_encode_none)
				? "none"
				: ((elem_type->u.basic.integer.encoding == lttng_encode_UTF8)
					? "UTF8"
					: "ASCII"),
			elem_type->u.basic.integer.base,
#if (BYTE_ORDER == BIG_ENDIAN)
			elem_type->u.basic.integer.reverse_byte_order ? " byte_order = le;" : "",
#else
			elem_type->u.basic.integer.reverse_byte_order ? " byte_order = be;" : "",
#endif
			field->name,
			field->name);
		break;
	}

	case atype_string:
		/* Default encoding is UTF8 */
		ret = lttng_metadata_printf(session,
			"		string%s _%s;\n",
			field->type.u.basic.string.encoding == lttng_encode_ASCII ?
				" { encoding = ASCII; }" : "",
			field->name);
		break;
	default:
		WARN_ON_ONCE(1);
		return -EINVAL;
	}
	return ret;
}

static
int _lttng_context_metadata_statedump(struct lttng_session *session,
				    struct lttng_ctx *ctx)
{
	int ret = 0;
	int i;

	if (!ctx)
		return 0;
	for (i = 0; i < ctx->nr_fields; i++) {
		const struct lttng_ctx_field *field = &ctx->fields[i];

		ret = _lttng_field_statedump(session, &field->event_field);
		if (ret)
			return ret;
	}
	return ret;
}

static
int _lttng_fields_metadata_statedump(struct lttng_session *session,
				   struct lttng_event *event)
{
	const struct lttng_event_desc *desc = event->desc;
	int ret = 0;
	int i;

	for (i = 0; i < desc->nr_fields; i++) {
		const struct lttng_event_field *field = &desc->fields[i];

		ret = _lttng_field_statedump(session, field);
		if (ret)
			return ret;
	}
	return ret;
}

static
int _lttng_event_metadata_statedump(struct lttng_session *session,
				  struct lttng_channel *chan,
				  struct lttng_event *event)
{
	int ret = 0;
	int loglevel = TRACE_DEFAULT;

	if (event->metadata_dumped || !CMM_ACCESS_ONCE(session->active))
		return 0;
	if (chan == session->metadata)
		return 0;
	/*
	 * Don't print events for which probe load is pending.
	 */
	if (!event->desc)
		return 0;

	ret = lttng_metadata_printf(session,
		"event {\n"
		"	name = \"%s\";\n"
		"	id = %u;\n"
		"	stream_id = %u;\n",
		event->desc->name,
		event->id,
		event->chan->id);
	if (ret)
		goto end;

	if (event->desc->loglevel)
		loglevel = *(*event->desc->loglevel);

	ret = lttng_metadata_printf(session,
		"	loglevel = %d;\n",
		loglevel);
	if (ret)
		goto end;

	if (event->desc->u.ext.model_emf_uri) {
		ret = lttng_metadata_printf(session,
			"	model.emf.uri = \"%s\";\n",
			*(event->desc->u.ext.model_emf_uri));
		if (ret)
			goto end;
	}

	if (event->ctx) {
		ret = lttng_metadata_printf(session,
			"	context := struct {\n");
		if (ret)
			goto end;
	}
	ret = _lttng_context_metadata_statedump(session, event->ctx);
	if (ret)
		goto end;
	if (event->ctx) {
		ret = lttng_metadata_printf(session,
			"	};\n");
		if (ret)
			goto end;
	}

	ret = lttng_metadata_printf(session,
		"	fields := struct {\n"
		);
	if (ret)
		goto end;

	ret = _lttng_fields_metadata_statedump(session, event);
	if (ret)
		goto end;

	/*
	 * LTTng space reservation can only reserve multiples of the
	 * byte size.
	 */
	ret = lttng_metadata_printf(session,
		"	};\n"
		"};\n\n");
	if (ret)
		goto end;

	event->metadata_dumped = 1;
end:
	return ret;

}

static
int _lttng_channel_metadata_statedump(struct lttng_session *session,
				    struct lttng_channel *chan)
{
	int ret = 0;

	if (chan->metadata_dumped || !CMM_ACCESS_ONCE(session->active))
		return 0;
	if (chan == session->metadata)
		return 0;

	WARN_ON_ONCE(!chan->header_type);
	ret = lttng_metadata_printf(session,
		"stream {\n"
		"	id = %u;\n"
		"	event.header := %s;\n"
		"	packet.context := struct packet_context;\n",
		chan->id,
		chan->header_type == 1 ? "struct event_header_compact" :
			"struct event_header_large");
	if (ret)
		goto end;

	if (chan->ctx) {
		ret = lttng_metadata_printf(session,
			"	event.context := struct {\n");
		if (ret)
			goto end;
	}
	ret = _lttng_context_metadata_statedump(session, chan->ctx);
	if (ret)
		goto end;
	if (chan->ctx) {
		ret = lttng_metadata_printf(session,
			"	};\n");
		if (ret)
			goto end;
	}

	ret = lttng_metadata_printf(session,
		"};\n\n");

	chan->metadata_dumped = 1;
end:
	return ret;
}

static
int _lttng_stream_packet_context_declare(struct lttng_session *session)
{
	return lttng_metadata_printf(session,
		"struct packet_context {\n"
		"	uint64_clock_monotonic_t timestamp_begin;\n"
		"	uint64_clock_monotonic_t timestamp_end;\n"
		"	uint64_t content_size;\n"
		"	uint64_t packet_size;\n"
		"	unsigned long events_discarded;\n"
		"	uint32_t cpu_id;\n"
		"};\n\n"
		);
}

/*
 * Compact header:
 * id: range: 0 - 30.
 * id 31 is reserved to indicate an extended header.
 *
 * Large header:
 * id: range: 0 - 65534.
 * id 65535 is reserved to indicate an extended header.
 */
static
int _lttng_event_header_declare(struct lttng_session *session)
{
	return lttng_metadata_printf(session,
	"struct event_header_compact {\n"
	"	enum : uint5_t { compact = 0 ... 30, extended = 31 } id;\n"
	"	variant <id> {\n"
	"		struct {\n"
	"			uint27_clock_monotonic_t timestamp;\n"
	"		} compact;\n"
	"		struct {\n"
	"			uint32_t id;\n"
	"			uint64_clock_monotonic_t timestamp;\n"
	"		} extended;\n"
	"	} v;\n"
	"} align(%u);\n"
	"\n"
	"struct event_header_large {\n"
	"	enum : uint16_t { compact = 0 ... 65534, extended = 65535 } id;\n"
	"	variant <id> {\n"
	"		struct {\n"
	"			uint32_clock_monotonic_t timestamp;\n"
	"		} compact;\n"
	"		struct {\n"
	"			uint32_t id;\n"
	"			uint64_clock_monotonic_t timestamp;\n"
	"		} extended;\n"
	"	} v;\n"
	"} align(%u);\n\n",
	lttng_alignof(uint32_t) * CHAR_BIT,
	lttng_alignof(uint16_t) * CHAR_BIT
	);
}

/*
 * Approximation of NTP time of day to clock monotonic correlation,
 * taken at start of trace.
 * Yes, this is only an approximation. Yes, we can (and will) do better
 * in future versions.
 */
static
uint64_t measure_clock_offset(void)
{
	uint64_t offset, monotonic[2], realtime;
	struct timespec rts = { 0, 0 };
	int ret;

	monotonic[0] = trace_clock_read64();
	ret = clock_gettime(CLOCK_REALTIME, &rts);	
	if (ret < 0)
		return 0;
	monotonic[1] = trace_clock_read64();
	offset = (monotonic[0] + monotonic[1]) >> 1;
	realtime = (uint64_t) rts.tv_sec * 1000000000ULL;
	realtime += rts.tv_nsec;
	offset = realtime - offset;
	return offset;
}

/*
 * Output metadata into this session's metadata buffers.
 */
static
int _lttng_session_metadata_statedump(struct lttng_session *session)
{
	unsigned char *uuid_c;
	char uuid_s[LTTNG_UST_UUID_STR_LEN],
		clock_uuid_s[LTTNG_UST_UUID_STR_LEN];
	struct lttng_channel *chan;
	struct lttng_event *event;
	int ret = 0;
	char procname[LTTNG_UST_PROCNAME_LEN] = "";
	char hostname[HOST_NAME_MAX];

	if (!CMM_ACCESS_ONCE(session->active))
		return 0;
	if (session->metadata_dumped)
		goto skip_session;
	if (!session->metadata) {
		DBG("LTTng: attempt to start tracing, but metadata channel is not found. Operation abort.\n");
		return -EPERM;
	}
	uuid_c = session->metadata->uuid;

	snprintf(uuid_s, sizeof(uuid_s),
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		uuid_c[0], uuid_c[1], uuid_c[2], uuid_c[3],
		uuid_c[4], uuid_c[5], uuid_c[6], uuid_c[7],
		uuid_c[8], uuid_c[9], uuid_c[10], uuid_c[11],
		uuid_c[12], uuid_c[13], uuid_c[14], uuid_c[15]);

	ret = lttng_metadata_printf(session,
		"typealias integer { size = 8; align = %u; signed = false; } := uint8_t;\n"
		"typealias integer { size = 16; align = %u; signed = false; } := uint16_t;\n"
		"typealias integer { size = 32; align = %u; signed = false; } := uint32_t;\n"
		"typealias integer { size = 64; align = %u; signed = false; } := uint64_t;\n"
		"typealias integer { size = %u; align = %u; signed = false; } := unsigned long;\n"
		"typealias integer { size = 5; align = 1; signed = false; } := uint5_t;\n"
		"typealias integer { size = 27; align = 1; signed = false; } := uint27_t;\n"
		"\n"
		"trace {\n"
		"	major = %u;\n"
		"	minor = %u;\n"
		"	uuid = \"%s\";\n"
		"	byte_order = %s;\n"
		"	packet.header := struct {\n"
		"		uint32_t magic;\n"
		"		uint8_t  uuid[16];\n"
		"		uint32_t stream_id;\n"
		"	};\n"
		"};\n\n",
		lttng_alignof(uint8_t) * CHAR_BIT,
		lttng_alignof(uint16_t) * CHAR_BIT,
		lttng_alignof(uint32_t) * CHAR_BIT,
		lttng_alignof(uint64_t) * CHAR_BIT,
		sizeof(unsigned long) * CHAR_BIT,
		lttng_alignof(unsigned long) * CHAR_BIT,
		CTF_SPEC_MAJOR,
		CTF_SPEC_MINOR,
		uuid_s,
#if (BYTE_ORDER == BIG_ENDIAN)
		"be"
#else
		"le"
#endif
		);
	if (ret)
		goto end;

	/* ignore error, just use empty string if error. */
	hostname[0] = '\0';
	ret = gethostname(hostname, sizeof(hostname));
	if (ret && errno == ENAMETOOLONG)
		hostname[HOST_NAME_MAX - 1] = '\0';
	lttng_ust_getprocname(procname);
	procname[LTTNG_UST_PROCNAME_LEN - 1] = '\0';
	ret = lttng_metadata_printf(session,
		"env {\n"
		"	hostname = \"%s\";\n"
		"	vpid = %d;\n"
		"	procname = \"%s\";\n"
		"	domain = \"ust\";\n"
		"	tracer_name = \"lttng-ust\";\n"
		"	tracer_major = %u;\n"
		"	tracer_minor = %u;\n"
		"	tracer_patchlevel = %u;\n"
		"};\n\n",
		hostname,
		(int) getpid(),
		procname,
		LTTNG_UST_MAJOR_VERSION,
		LTTNG_UST_MINOR_VERSION,
		LTTNG_UST_PATCHLEVEL_VERSION
		);
	if (ret)
		goto end;

	ret = lttng_metadata_printf(session,
		"clock {\n"
		"	name = %s;\n",
		"monotonic"
		);
	if (ret)
		goto end;

	if (!trace_clock_uuid(clock_uuid_s)) {
		ret = lttng_metadata_printf(session,
			"	uuid = \"%s\";\n",
			clock_uuid_s
			);
		if (ret)
			goto end;
	}

	ret = lttng_metadata_printf(session,
		"	description = \"Monotonic Clock\";\n"
		"	freq = %" PRIu64 "; /* Frequency, in Hz */\n"
		"	/* clock value offset from Epoch is: offset * (1/freq) */\n"
		"	offset = %" PRIu64 ";\n"
		"};\n\n",
		trace_clock_freq(),
		measure_clock_offset()
		);
	if (ret)
		goto end;

	ret = lttng_metadata_printf(session,
		"typealias integer {\n"
		"	size = 27; align = 1; signed = false;\n"
		"	map = clock.monotonic.value;\n"
		"} := uint27_clock_monotonic_t;\n"
		"\n"
		"typealias integer {\n"
		"	size = 32; align = %u; signed = false;\n"
		"	map = clock.monotonic.value;\n"
		"} := uint32_clock_monotonic_t;\n"
		"\n"
		"typealias integer {\n"
		"	size = 64; align = %u; signed = false;\n"
		"	map = clock.monotonic.value;\n"
		"} := uint64_clock_monotonic_t;\n\n",
		lttng_alignof(uint32_t) * CHAR_BIT,
		lttng_alignof(uint64_t) * CHAR_BIT
		);
	if (ret)
		goto end;

	ret = _lttng_stream_packet_context_declare(session);
	if (ret)
		goto end;

	ret = _lttng_event_header_declare(session);
	if (ret)
		goto end;

skip_session:
	cds_list_for_each_entry(chan, &session->chan_head, node) {
		ret = _lttng_channel_metadata_statedump(session, chan);
		if (ret)
			goto end;
	}

	cds_list_for_each_entry(event, &session->events_head, node) {
		ret = _lttng_event_metadata_statedump(session, event->chan, event);
		if (ret)
			goto end;
	}
	session->metadata_dumped = 1;
end:
	return ret;
}

void lttng_ust_events_exit(void)
{
	struct lttng_session *session, *tmpsession;

	cds_list_for_each_entry_safe(session, tmpsession, &sessions, node)
		lttng_session_destroy(session);
}

/*
 * Enabler management.
 */
struct lttng_enabler *lttng_enabler_create(enum lttng_enabler_type type,
		struct lttng_ust_event *event_param,
		struct lttng_channel *chan)
{
	struct lttng_enabler *enabler;

	enabler = zmalloc(sizeof(*enabler));
	if (!enabler)
		return NULL;
	enabler->type = type;
	CDS_INIT_LIST_HEAD(&enabler->filter_bytecode_head);
	memcpy(&enabler->event_param, event_param,
		sizeof(enabler->event_param));
	enabler->chan = chan;
	/* ctx left NULL */
	enabler->enabled = 1;
	cds_list_add(&enabler->node, &enabler->chan->session->enablers_head);
	lttng_session_lazy_sync_enablers(enabler->chan->session);
	return enabler;
}

int lttng_enabler_enable(struct lttng_enabler *enabler)
{
	enabler->enabled = 1;
	lttng_session_lazy_sync_enablers(enabler->chan->session);
	return 0;
}

int lttng_enabler_disable(struct lttng_enabler *enabler)
{
	if (enabler->chan == enabler->chan->session->metadata)
		return -EPERM;
	enabler->enabled = 0;
	lttng_session_lazy_sync_enablers(enabler->chan->session);
	return 0;
}

int lttng_enabler_attach_bytecode(struct lttng_enabler *enabler,
		struct lttng_ust_filter_bytecode_node *bytecode)
{
	bytecode->enabler = enabler;
	cds_list_add_tail(&bytecode->node, &enabler->filter_bytecode_head);
	lttng_session_lazy_sync_enablers(enabler->chan->session);
	return 0;
}

int lttng_attach_context(struct lttng_ust_context *context_param,
		struct lttng_ctx **ctx, struct lttng_session *session)
{
	/*
	 * We cannot attach a context after trace has been started for a
	 * session because the metadata does not allow expressing this
	 * information outside of the original channel scope.
	 */
	if (session->been_active)
		return -EPERM;

	switch (context_param->ctx) {
	case LTTNG_UST_CONTEXT_PTHREAD_ID:
		return lttng_add_pthread_id_to_ctx(ctx);
	case LTTNG_UST_CONTEXT_VTID:
		return lttng_add_vtid_to_ctx(ctx);
	case LTTNG_UST_CONTEXT_VPID:
		return lttng_add_vpid_to_ctx(ctx);
	case LTTNG_UST_CONTEXT_PROCNAME:
		return lttng_add_procname_to_ctx(ctx);
	default:
		return -EINVAL;
	}
}

int lttng_enabler_attach_context(struct lttng_enabler *enabler,
		struct lttng_ust_context *context_param)
{
#if 0	// disabled for now.
	struct lttng_session *session = enabler->chan->session;
	int ret;

	ret = lttng_attach_context(context_param, &enabler->ctx,
			session);
	if (ret)
		return ret;
	lttng_session_lazy_sync_enablers(enabler->chan->session);
#endif
	return -ENOSYS;
}

static
void lttng_enabler_destroy(struct lttng_enabler *enabler)
{
	struct lttng_ust_filter_bytecode_node *filter_node, *tmp_filter_node;

	/* Destroy filter bytecode */
	cds_list_for_each_entry_safe(filter_node, tmp_filter_node,
			&enabler->filter_bytecode_head, node) {
		free(filter_node);
	}

	/* Destroy contexts */
	lttng_destroy_context(enabler->ctx);

	cds_list_del(&enabler->node);
	free(enabler);
}

/*
 * lttng_session_sync_enablers should be called just before starting a
 * session.
 */
static
void lttng_session_sync_enablers(struct lttng_session *session)
{
	struct lttng_enabler *enabler;
	struct lttng_event *event;

	cds_list_for_each_entry(enabler, &session->enablers_head, node)
		lttng_enabler_ref_events(enabler);
	/*
	 * For each event, if at least one of its enablers is enabled,
	 * we enable the event, else we disable it.
	 */
	cds_list_for_each_entry(event, &session->events_head, node) {
		struct lttng_enabler_ref *enabler_ref;
		struct lttng_bytecode_runtime *runtime;
		int enabled = 0, has_enablers_without_bytecode = 0;

		/* Enable events */
		cds_list_for_each_entry(enabler_ref,
				&event->enablers_ref_head, node) {
			if (enabler_ref->ref->enabled) {
				enabled = 1;
				break;
			}
		}
		event->enabled = enabled;

		/* Check if has enablers without bytecode enabled */
		cds_list_for_each_entry(enabler_ref,
				&event->enablers_ref_head, node) {
			if (enabler_ref->ref->enabled
					&& cds_list_empty(&enabler_ref->ref->filter_bytecode_head)) {
				has_enablers_without_bytecode = 1;
				break;
			}
		}
		event->has_enablers_without_bytecode =
			has_enablers_without_bytecode;

		/* Enable filters */
		cds_list_for_each_entry(runtime,
				&event->bytecode_runtime_head, node) {
			lttng_filter_sync_state(runtime);
		}
	}
}

/*
 * Apply enablers to session events, adding events to session if need
 * be. It is required after each modification applied to an active
 * session, and right before session "start".
 * "lazy" sync means we only sync if required.
 */
static
void lttng_session_lazy_sync_enablers(struct lttng_session *session)
{
	/* We can skip if session is not active */
	if (!session->active)
		return;
	lttng_session_sync_enablers(session);
}
