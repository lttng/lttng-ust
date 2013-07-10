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
#include <lttng/ust-ctl.h>
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

static
void register_event(struct lttng_event *event)
{
	int ret;
	const struct lttng_event_desc *desc;

	assert(event->registered == 0);
	desc = event->desc;
	ret = __tracepoint_probe_register(desc->name,
			desc->probe_callback,
			event, desc->signature);
	WARN_ON_ONCE(ret);
	if (!ret)
		event->registered = 1;
}

static
void unregister_event(struct lttng_event *event)
{
	int ret;
	const struct lttng_event_desc *desc;

	assert(event->registered == 1);
	desc = event->desc;
	ret = __tracepoint_probe_unregister(desc->name,
			desc->probe_callback,
			event);
	WARN_ON_ONCE(ret);
	if (!ret)
		event->registered = 0;
}

/*
 * Only used internally at session destruction.
 */
static
void _lttng_event_unregister(struct lttng_event *event)
{
	if (event->registered)
		unregister_event(event);
}

void lttng_session_destroy(struct lttng_session *session)
{
	struct lttng_channel *chan, *tmpchan;
	struct lttng_event *event, *tmpevent;
	struct lttng_enabler *enabler, *tmpenabler;

	CMM_ACCESS_ONCE(session->active) = 0;
	cds_list_for_each_entry(event, &session->events_head, node) {
		_lttng_event_unregister(event);
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

	/* Set transient enabler state to "enabled" */
	session->tstate = 1;
	/* We need to sync enablers with session before activation. */
	lttng_session_sync_enablers(session);

	/*
	 * Snapshot the number of events per channel to know the type of header
	 * we need to use.
	 */
	cds_list_for_each_entry(chan, &session->chan_head, node) {
		const struct lttng_ctx *ctx;
		const struct lttng_ctx_field *fields = NULL;
		size_t nr_fields = 0;
		uint32_t chan_id;

		/* don't change it if session stop/restart */
		if (chan->header_type)
			continue;
		ctx = chan->ctx;
		if (ctx) {
			nr_fields = ctx->nr_fields;
			fields = ctx->fields;
		}
		ret = ustcomm_register_channel(notify_socket,
			session->objd,
			chan->objd,
			nr_fields,
			fields,
			&chan_id,
			&chan->header_type);
		if (ret) {
			DBG("Error (%d) registering channel to sessiond", ret);
			return ret;
		}
		if (chan_id != chan->id) {
			DBG("Error: channel registration id (%u) does not match id assigned at creation (%u)",
				chan_id, chan->id);
			return -EINVAL;
		}
	}

	/* Set atomically the state to "active" */
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
	/* Set atomically the state to "inactive" */
	CMM_ACCESS_ONCE(session->active) = 0;

	/* Set transient enabler state to "disabled" */
	session->tstate = 0;
	lttng_session_sync_enablers(session);
end:
	return ret;
}

int lttng_channel_enable(struct lttng_channel *channel)
{
	int ret = 0;

	if (channel->enabled) {
		ret = -EBUSY;
		goto end;
	}
	/* Set transient enabler state to "enabled" */
	channel->tstate = 1;
	lttng_session_sync_enablers(channel->session);
	/* Set atomically the state to "enabled" */
	CMM_ACCESS_ONCE(channel->enabled) = 1;
end:
	return ret;
}

int lttng_channel_disable(struct lttng_channel *channel)
{
	int ret = 0;

	if (!channel->enabled) {
		ret = -EBUSY;
		goto end;
	}
	/* Set atomically the state to "disabled" */
	CMM_ACCESS_ONCE(channel->enabled) = 0;
	/* Set transient enabler state to "enabled" */
	channel->tstate = 0;
	lttng_session_sync_enablers(channel->session);
end:
	return ret;
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
		if (!strncmp(event->desc->name, desc->name,
					LTTNG_UST_SYM_NAME_LEN - 1)
				&& chan == event->chan) {
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

	/* Event will be enabled by enabler sync. */
	event->enabled = 0;
	event->registered = 0;
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
		DBG("Error (%d) registering event to sessiond", ret);
		goto sessiond_register_error;
	}

	/* Populate lttng_event structure before tracepoint registration. */
	cmm_smp_wmb();
	cds_list_add(&event->node, &chan->session->events_head);
	cds_hlist_add_head(&event->hlist, head);
	return 0;

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
	unsigned int has_loglevel = 0;

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
	if (lttng_desc_match_enabler(event->desc, enabler)
			&& event->chan == enabler->chan)
		return 1;
	else
		return 0;
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
				if (event->desc == desc
						&& event->chan == enabler->chan)
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
 * Called with session mutex held.
 */
int lttng_fix_pending_events(void)
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
	case LTTNG_UST_CONTEXT_IP:
		return lttng_add_ip_to_ctx(ctx);
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
	 * and its channel and session transient states are enabled, we
	 * enable the event, else we disable it.
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
		/*
		 * Enabled state is based on union of enablers, with
		 * intesection of session and channel transient enable
		 * states.
		 */
		enabled = enabled && session->tstate && event->chan->tstate;

		CMM_STORE_SHARED(event->enabled, enabled);
		/*
		 * Sync tracepoint registration with event enabled
		 * state.
		 */
		if (enabled) {
			if (!event->registered)
				register_event(event);
		} else {
			if (event->registered)
				unregister_event(event);
		}

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
