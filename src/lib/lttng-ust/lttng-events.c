/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2010-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Holds LTTng per-session event registry.
 */

#define _LGPL_SOURCE
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <sys/shm.h>
#include <sys/ipc.h>
#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>
#include <time.h>
#include <stdbool.h>
#include <unistd.h>
#include <dlfcn.h>
#include <lttng/ust-endian.h>

#include <urcu/arch.h>
#include <urcu/compiler.h>
#include <urcu/hlist.h>
#include <urcu/list.h>
#include <urcu/uatomic.h>

#include <lttng/tracepoint.h>
#include <lttng/ust-events.h>

#include "common/logging.h"
#include "common/macros.h"
#include <lttng/ust-ctl.h>
#include "common/ustcomm.h"
#include "common/ust-fd.h"
#include "common/dynamic-type.h"
#include "common/ust-context-provider.h"
#include "lttng-ust-uuid.h"

#include "common/tracepoint.h"
#include "common/strutils.h"
#include "lttng-bytecode.h"
#include "lttng-tracer.h"
#include "lttng-tracer-core.h"
#include "lttng-ust-statedump.h"
#include "context-internal.h"
#include "lib/lttng-ust/events.h"
#include "common/ringbuffer/shm.h"
#include "common/ringbuffer/frontend_types.h"
#include "common/ringbuffer/frontend.h"
#include "common/counter/counter.h"
#include "common/jhash.h"
#include <lttng/ust-abi.h>
#include "context-provider-internal.h"

/*
 * All operations within this file are called by the communication
 * thread, under ust_lock protection.
 */

static CDS_LIST_HEAD(sessions);
static CDS_LIST_HEAD(event_notifier_groups);

struct cds_list_head *lttng_get_sessions(void)
{
	return &sessions;
}

static void _lttng_event_destroy(struct lttng_ust_event_common *event);
static void _lttng_enum_destroy(struct lttng_enum *_enum);

static
void lttng_session_lazy_sync_event_enablers(struct lttng_ust_session *session);
static
void lttng_session_sync_event_enablers(struct lttng_ust_session *session);
static
void lttng_event_notifier_group_sync_enablers(
		struct lttng_event_notifier_group *event_notifier_group);
static
void lttng_enabler_destroy(struct lttng_enabler *enabler);

bool lttng_ust_validate_event_name(const struct lttng_ust_event_desc *desc)
{
	if (strlen(desc->probe_desc->provider_name) + 1 +
			strlen(desc->event_name) >= LTTNG_UST_ABI_SYM_NAME_LEN)
		return false;
	return true;
}

void lttng_ust_format_event_name(const struct lttng_ust_event_desc *desc,
		char *name)
{
	strcpy(name, desc->probe_desc->provider_name);
	strcat(name, ":");
	strcat(name, desc->event_name);
}

/*
 * Called with ust lock held.
 */
int lttng_session_active(void)
{
	struct lttng_ust_session_private *iter;

	cds_list_for_each_entry(iter, &sessions, node) {
		if (iter->pub->active)
			return 1;
	}
	return 0;
}

static
int lttng_loglevel_match(int loglevel,
		unsigned int has_loglevel,
		enum lttng_ust_abi_loglevel_type req_type,
		int req_loglevel)
{
	if (!has_loglevel)
		loglevel = TRACE_DEFAULT;
	switch (req_type) {
	case LTTNG_UST_ABI_LOGLEVEL_RANGE:
		if (loglevel <= req_loglevel
				|| (req_loglevel == -1 && loglevel <= TRACE_DEBUG))
			return 1;
		else
			return 0;
	case LTTNG_UST_ABI_LOGLEVEL_SINGLE:
		if (loglevel == req_loglevel
				|| (req_loglevel == -1 && loglevel <= TRACE_DEBUG))
			return 1;
		else
			return 0;
	case LTTNG_UST_ABI_LOGLEVEL_ALL:
	default:
		if (loglevel <= TRACE_DEBUG)
			return 1;
		else
			return 0;
	}
}

struct lttng_ust_session *lttng_session_create(void)
{
	struct lttng_ust_session *session;
	struct lttng_ust_session_private *session_priv;
	int i;

	session = zmalloc(sizeof(struct lttng_ust_session));
	if (!session)
		return NULL;
	session->struct_size = sizeof(struct lttng_ust_session);
	session_priv = zmalloc(sizeof(struct lttng_ust_session_private));
	if (!session_priv) {
		free(session);
		return NULL;
	}
	session->priv = session_priv;
	session_priv->pub = session;
	if (lttng_context_init_all(&session->priv->ctx)) {
		free(session_priv);
		free(session);
		return NULL;
	}
	CDS_INIT_LIST_HEAD(&session->priv->chan_head);
	CDS_INIT_LIST_HEAD(&session->priv->events_head);
	CDS_INIT_LIST_HEAD(&session->priv->enums_head);
	CDS_INIT_LIST_HEAD(&session->priv->enablers_head);
	for (i = 0; i < LTTNG_UST_EVENT_HT_SIZE; i++)
		CDS_INIT_HLIST_HEAD(&session->priv->events_ht.table[i]);
	for (i = 0; i < LTTNG_UST_ENUM_HT_SIZE; i++)
		CDS_INIT_HLIST_HEAD(&session->priv->enums_ht.table[i]);
	cds_list_add(&session->priv->node, &sessions);
	return session;
}

struct lttng_counter *lttng_ust_counter_create(
		const char *counter_transport_name,
		size_t number_dimensions, const struct lttng_counter_dimension *dimensions)
{
	struct lttng_counter_transport *counter_transport = NULL;
	struct lttng_counter *counter = NULL;

	counter_transport = lttng_counter_transport_find(counter_transport_name);
	if (!counter_transport)
		goto notransport;
	counter = zmalloc(sizeof(struct lttng_counter));
	if (!counter)
		goto nomem;

	counter->ops = &counter_transport->ops;
	counter->transport = counter_transport;

	counter->counter = counter->ops->counter_create(
			number_dimensions, dimensions, 0,
			-1, 0, NULL, false);
	if (!counter->counter) {
		goto create_error;
	}

	return counter;

create_error:
	free(counter);
nomem:
notransport:
	return NULL;
}

static
void lttng_ust_counter_destroy(struct lttng_counter *counter)
{
	counter->ops->counter_destroy(counter->counter);
	free(counter);
}

struct lttng_event_notifier_group *lttng_event_notifier_group_create(void)
{
	struct lttng_event_notifier_group *event_notifier_group;
	int i;

	event_notifier_group = zmalloc(sizeof(struct lttng_event_notifier_group));
	if (!event_notifier_group)
		return NULL;

	/* Add all contexts. */
	if (lttng_context_init_all(&event_notifier_group->ctx)) {
		free(event_notifier_group);
		return NULL;
	}

	CDS_INIT_LIST_HEAD(&event_notifier_group->enablers_head);
	CDS_INIT_LIST_HEAD(&event_notifier_group->event_notifiers_head);
	for (i = 0; i < LTTNG_UST_EVENT_NOTIFIER_HT_SIZE; i++)
		CDS_INIT_HLIST_HEAD(&event_notifier_group->event_notifiers_ht.table[i]);

	cds_list_add(&event_notifier_group->node, &event_notifier_groups);

	return event_notifier_group;
}

/*
 * Only used internally at session destruction.
 */
static
void _lttng_channel_unmap(struct lttng_ust_channel_buffer *lttng_chan)
{
	struct lttng_ust_ring_buffer_channel *chan;
	struct lttng_ust_shm_handle *handle;

	cds_list_del(&lttng_chan->priv->node);
	lttng_destroy_context(lttng_chan->priv->ctx);
	chan = lttng_chan->priv->rb_chan;
	handle = chan->handle;
	channel_destroy(chan, handle, 0);
	free(lttng_chan->parent);
	free(lttng_chan->priv);
	free(lttng_chan);
}

static
void register_event(struct lttng_ust_event_common *event)
{
	int ret;
	const struct lttng_ust_event_desc *desc;

	assert(event->priv->registered == 0);
	desc = event->priv->desc;
	ret = lttng_ust_tp_probe_register_queue_release(desc->probe_desc->provider_name,
			desc->event_name,
			desc->probe_callback,
			event, desc->signature);
	WARN_ON_ONCE(ret);
	if (!ret)
		event->priv->registered = 1;
}

static
void unregister_event(struct lttng_ust_event_common *event)
{
	int ret;
	const struct lttng_ust_event_desc *desc;

	assert(event->priv->registered == 1);
	desc = event->priv->desc;
	ret = lttng_ust_tp_probe_unregister_queue_release(desc->probe_desc->provider_name,
			desc->event_name,
			desc->probe_callback,
			event);
	WARN_ON_ONCE(ret);
	if (!ret)
		event->priv->registered = 0;
}

static
void _lttng_event_unregister(struct lttng_ust_event_common *event)
{
	if (event->priv->registered)
		unregister_event(event);
}

void lttng_session_destroy(struct lttng_ust_session *session)
{
	struct lttng_ust_channel_buffer_private *chan, *tmpchan;
	struct lttng_ust_event_recorder_private *event_recorder_priv, *tmpevent_recorder_priv;
	struct lttng_enum *_enum, *tmp_enum;
	struct lttng_event_enabler *event_enabler, *event_tmpenabler;

	CMM_ACCESS_ONCE(session->active) = 0;
	cds_list_for_each_entry(event_recorder_priv, &session->priv->events_head, node) {
		_lttng_event_unregister(event_recorder_priv->parent.pub);
	}
	lttng_ust_urcu_synchronize_rcu();	/* Wait for in-flight events to complete */
	lttng_ust_tp_probe_prune_release_queue();
	cds_list_for_each_entry_safe(event_enabler, event_tmpenabler,
			&session->priv->enablers_head, node)
		lttng_event_enabler_destroy(event_enabler);
	cds_list_for_each_entry_safe(event_recorder_priv, tmpevent_recorder_priv,
			&session->priv->events_head, node)
		_lttng_event_destroy(event_recorder_priv->parent.pub);
	cds_list_for_each_entry_safe(_enum, tmp_enum,
			&session->priv->enums_head, node)
		_lttng_enum_destroy(_enum);
	cds_list_for_each_entry_safe(chan, tmpchan, &session->priv->chan_head, node)
		_lttng_channel_unmap(chan->pub);
	cds_list_del(&session->priv->node);
	lttng_destroy_context(session->priv->ctx);
	free(session->priv);
	free(session);
}

void lttng_event_notifier_group_destroy(
		struct lttng_event_notifier_group *event_notifier_group)
{
	int close_ret;
	struct lttng_event_notifier_enabler *notifier_enabler, *tmpnotifier_enabler;
	struct lttng_ust_event_notifier_private *event_notifier_priv, *tmpevent_notifier_priv;

	if (!event_notifier_group) {
		return;
	}

	cds_list_for_each_entry(event_notifier_priv,
			&event_notifier_group->event_notifiers_head, node)
		_lttng_event_unregister(event_notifier_priv->parent.pub);

	lttng_ust_urcu_synchronize_rcu();

	cds_list_for_each_entry_safe(notifier_enabler, tmpnotifier_enabler,
			&event_notifier_group->enablers_head, node)
		lttng_event_notifier_enabler_destroy(notifier_enabler);

	cds_list_for_each_entry_safe(event_notifier_priv, tmpevent_notifier_priv,
			&event_notifier_group->event_notifiers_head, node)
		_lttng_event_destroy(event_notifier_priv->parent.pub);

	if (event_notifier_group->error_counter)
		lttng_ust_counter_destroy(event_notifier_group->error_counter);

	/* Close the notification fd to the listener of event_notifiers. */

	lttng_ust_lock_fd_tracker();
	close_ret = close(event_notifier_group->notification_fd);
	if (!close_ret) {
		lttng_ust_delete_fd_from_tracker(
				event_notifier_group->notification_fd);
	} else {
		PERROR("close");
		abort();
	}
	lttng_ust_unlock_fd_tracker();

	cds_list_del(&event_notifier_group->node);
	lttng_destroy_context(event_notifier_group->ctx);
	free(event_notifier_group);
}

static
void lttng_enabler_destroy(struct lttng_enabler *enabler)
{
	struct lttng_ust_bytecode_node *filter_node, *tmp_filter_node;
	struct lttng_ust_excluder_node *excluder_node, *tmp_excluder_node;

	if (!enabler) {
		return;
	}

	/* Destroy filter bytecode */
	cds_list_for_each_entry_safe(filter_node, tmp_filter_node,
			&enabler->filter_bytecode_head, node) {
		free(filter_node);
	}

	/* Destroy excluders */
	cds_list_for_each_entry_safe(excluder_node, tmp_excluder_node,
			&enabler->excluder_head, node) {
		free(excluder_node);
	}
}

 void lttng_event_notifier_enabler_destroy(struct lttng_event_notifier_enabler *event_notifier_enabler)
{
	if (!event_notifier_enabler) {
		return;
	}

	cds_list_del(&event_notifier_enabler->node);

	lttng_enabler_destroy(lttng_event_notifier_enabler_as_enabler(event_notifier_enabler));

	free(event_notifier_enabler);
}

static
int lttng_enum_create(const struct lttng_ust_enum_desc *desc,
		struct lttng_ust_session *session)
{
	const char *enum_name = desc->name;
	struct lttng_enum *_enum;
	struct cds_hlist_head *head;
	int ret = 0;
	size_t name_len = strlen(enum_name);
	uint32_t hash;
	int notify_socket;

	/* Check if this enum is already registered for this session. */
	hash = jhash(enum_name, name_len, 0);
	head = &session->priv->enums_ht.table[hash & (LTTNG_UST_ENUM_HT_SIZE - 1)];

	_enum = lttng_ust_enum_get_from_desc(session, desc);
	if (_enum) {
		ret = -EEXIST;
		goto exist;
	}

	notify_socket = lttng_get_notify_socket(session->priv->owner);
	if (notify_socket < 0) {
		ret = notify_socket;
		goto socket_error;
	}

	_enum = zmalloc(sizeof(*_enum));
	if (!_enum) {
		ret = -ENOMEM;
		goto cache_error;
	}
	_enum->session = session;
	_enum->desc = desc;

	ret = ustcomm_register_enum(notify_socket,
		session->priv->objd,
		enum_name,
		desc->nr_entries,
		desc->entries,
		&_enum->id);
	if (ret < 0) {
		DBG("Error (%d) registering enumeration to sessiond", ret);
		goto sessiond_register_error;
	}
	cds_list_add(&_enum->node, &session->priv->enums_head);
	cds_hlist_add_head(&_enum->hlist, head);
	return 0;

sessiond_register_error:
	free(_enum);
cache_error:
socket_error:
exist:
	return ret;
}

static
int lttng_create_enum_check(const struct lttng_ust_type_common *type,
		struct lttng_ust_session *session)
{
	switch (type->type) {
	case lttng_ust_type_enum:
	{
		const struct lttng_ust_enum_desc *enum_desc;
		int ret;

		enum_desc = lttng_ust_get_type_enum(type)->desc;
		ret = lttng_enum_create(enum_desc, session);
		if (ret && ret != -EEXIST) {
			DBG("Unable to create enum error: (%d)", ret);
			return ret;
		}
		break;
	}
	case lttng_ust_type_dynamic:
	{
		const struct lttng_ust_event_field *tag_field_generic;
		const struct lttng_ust_enum_desc *enum_desc;
		int ret;

		tag_field_generic = lttng_ust_dynamic_type_tag_field();
		enum_desc = lttng_ust_get_type_enum(tag_field_generic->type)->desc;
		ret = lttng_enum_create(enum_desc, session);
		if (ret && ret != -EEXIST) {
			DBG("Unable to create enum error: (%d)", ret);
			return ret;
		}
		break;
	}
	default:
		/* TODO: nested types when they become supported. */
		break;
	}
	return 0;
}

static
int lttng_create_all_event_enums(size_t nr_fields,
		const struct lttng_ust_event_field * const *event_fields,
		struct lttng_ust_session *session)
{
	size_t i;
	int ret;

	/* For each field, ensure enum is part of the session. */
	for (i = 0; i < nr_fields; i++) {
		const struct lttng_ust_type_common *type = event_fields[i]->type;

		ret = lttng_create_enum_check(type, session);
		if (ret)
			return ret;
	}
	return 0;
}

static
int lttng_create_all_ctx_enums(size_t nr_fields,
		struct lttng_ust_ctx_field *ctx_fields,
		struct lttng_ust_session *session)
{
	size_t i;
	int ret;

	/* For each field, ensure enum is part of the session. */
	for (i = 0; i < nr_fields; i++) {
		const struct lttng_ust_type_common *type = ctx_fields[i].event_field->type;

		ret = lttng_create_enum_check(type, session);
		if (ret)
			return ret;
	}
	return 0;
}

/*
 * Ensure that a state-dump will be performed for this session at the end
 * of the current handle_message().
 */
int lttng_session_statedump(struct lttng_ust_session *session)
{
	session->priv->statedump_pending = 1;
	lttng_ust_sockinfo_session_enabled(session->priv->owner);
	return 0;
}

int lttng_session_enable(struct lttng_ust_session *session)
{
	int ret = 0;
	struct lttng_ust_channel_buffer_private *chan;
	int notify_socket;

	if (session->active) {
		ret = -EBUSY;
		goto end;
	}

	notify_socket = lttng_get_notify_socket(session->priv->owner);
	if (notify_socket < 0)
		return notify_socket;

	/* Set transient enabler state to "enabled" */
	session->priv->tstate = 1;

	/* We need to sync enablers with session before activation. */
	lttng_session_sync_event_enablers(session);

	/*
	 * Snapshot the number of events per channel to know the type of header
	 * we need to use.
	 */
	cds_list_for_each_entry(chan, &session->priv->chan_head, node) {
		struct lttng_ust_ctx *ctx;
		struct lttng_ust_ctx_field *fields = NULL;
		size_t nr_fields = 0;
		uint32_t chan_id;

		/* don't change it if session stop/restart */
		if (chan->header_type)
			continue;
		ctx = chan->ctx;
		if (ctx) {
			nr_fields = ctx->nr_fields;
			fields = ctx->fields;
			ret = lttng_create_all_ctx_enums(nr_fields, fields,
				session);
			if (ret < 0) {
				DBG("Error (%d) adding enum to session", ret);
				return ret;
			}
		}
		ret = ustcomm_register_channel(notify_socket,
			session,
			session->priv->objd,
			chan->parent.objd,
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
	CMM_ACCESS_ONCE(session->priv->been_active) = 1;

	ret = lttng_session_statedump(session);
	if (ret)
		return ret;
end:
	return ret;
}

int lttng_session_disable(struct lttng_ust_session *session)
{
	int ret = 0;

	if (!session->active) {
		ret = -EBUSY;
		goto end;
	}
	/* Set atomically the state to "inactive" */
	CMM_ACCESS_ONCE(session->active) = 0;

	/* Set transient enabler state to "disabled" */
	session->priv->tstate = 0;
	lttng_session_sync_event_enablers(session);
end:
	return ret;
}

int lttng_channel_enable(struct lttng_ust_channel_common *lttng_channel)
{
	int ret = 0;

	if (lttng_channel->enabled) {
		ret = -EBUSY;
		goto end;
	}
	/* Set transient enabler state to "enabled" */
	lttng_channel->priv->tstate = 1;
	lttng_session_sync_event_enablers(lttng_channel->session);
	/* Set atomically the state to "enabled" */
	CMM_ACCESS_ONCE(lttng_channel->enabled) = 1;
end:
	return ret;
}

int lttng_channel_disable(struct lttng_ust_channel_common *lttng_channel)
{
	int ret = 0;

	if (!lttng_channel->enabled) {
		ret = -EBUSY;
		goto end;
	}
	/* Set atomically the state to "disabled" */
	CMM_ACCESS_ONCE(lttng_channel->enabled) = 0;
	/* Set transient enabler state to "enabled" */
	lttng_channel->priv->tstate = 0;
	lttng_session_sync_event_enablers(lttng_channel->session);
end:
	return ret;
}

static inline
struct cds_hlist_head *borrow_hash_table_bucket(
		struct cds_hlist_head *hash_table,
		unsigned int hash_table_size,
		const struct lttng_ust_event_desc *desc)
{
	char name[LTTNG_UST_ABI_SYM_NAME_LEN];
	size_t name_len;
	uint32_t hash;

	lttng_ust_format_event_name(desc, name);
	name_len = strlen(name);

	hash = jhash(name, name_len, 0);
	return &hash_table[hash & (hash_table_size - 1)];
}

/*
 * Supports event creation while tracing session is active.
 */
static
int lttng_event_recorder_create(const struct lttng_ust_event_desc *desc,
		struct lttng_ust_channel_buffer *chan)
{
	char name[LTTNG_UST_ABI_SYM_NAME_LEN];
	struct lttng_ust_event_recorder *event_recorder;
	struct lttng_ust_event_recorder_private *event_recorder_priv;
	struct lttng_ust_session *session = chan->parent->session;
	struct cds_hlist_head *head;
	int ret = 0;
	int notify_socket, loglevel;
	const char *uri;

	head = borrow_hash_table_bucket(chan->parent->session->priv->events_ht.table,
		LTTNG_UST_EVENT_HT_SIZE, desc);

	notify_socket = lttng_get_notify_socket(session->priv->owner);
	if (notify_socket < 0) {
		ret = notify_socket;
		goto socket_error;
	}

	ret = lttng_create_all_event_enums(desc->nr_fields, desc->fields,
			session);
	if (ret < 0) {
		DBG("Error (%d) adding enum to session", ret);
		goto create_enum_error;
	}

	/*
	 * Check if loglevel match. Refuse to connect event if not.
	 */
	event_recorder = zmalloc(sizeof(struct lttng_ust_event_recorder));
	if (!event_recorder) {
		ret = -ENOMEM;
		goto cache_error;
	}
	event_recorder->struct_size = sizeof(struct lttng_ust_event_recorder);

	event_recorder->parent = zmalloc(sizeof(struct lttng_ust_event_common));
	if (!event_recorder->parent) {
		ret = -ENOMEM;
		goto parent_error;
	}
	event_recorder->parent->struct_size = sizeof(struct lttng_ust_event_common);
	event_recorder->parent->type = LTTNG_UST_EVENT_TYPE_RECORDER;
	event_recorder->parent->child = event_recorder;

	event_recorder_priv = zmalloc(sizeof(struct lttng_ust_event_recorder_private));
	if (!event_recorder_priv) {
		ret = -ENOMEM;
		goto priv_error;
	}
	event_recorder->priv = event_recorder_priv;
	event_recorder_priv->pub = event_recorder;
	event_recorder->parent->priv = &event_recorder_priv->parent;
	event_recorder_priv->parent.pub = event_recorder->parent;

	event_recorder->chan = chan;

	/* Event will be enabled by enabler sync. */
	event_recorder->parent->run_filter = lttng_ust_interpret_event_filter;
	event_recorder->parent->enabled = 0;
	event_recorder->parent->priv->registered = 0;
	CDS_INIT_LIST_HEAD(&event_recorder->parent->priv->filter_bytecode_runtime_head);
	CDS_INIT_LIST_HEAD(&event_recorder->parent->priv->enablers_ref_head);
	event_recorder->parent->priv->desc = desc;

	if (desc->loglevel)
		loglevel = *(*desc->loglevel);
	else
		loglevel = TRACE_DEFAULT;
	if (desc->model_emf_uri)
		uri = *(desc->model_emf_uri);
	else
		uri = NULL;

	lttng_ust_format_event_name(desc, name);

	/* Fetch event ID from sessiond */
	ret = ustcomm_register_event(notify_socket,
		session,
		session->priv->objd,
		chan->priv->parent.objd,
		name,
		loglevel,
		desc->signature,
		desc->nr_fields,
		desc->fields,
		uri,
		&event_recorder->priv->id);
	if (ret < 0) {
		DBG("Error (%d) registering event to sessiond", ret);
		goto sessiond_register_error;
	}

	cds_list_add(&event_recorder_priv->node, &chan->parent->session->priv->events_head);
	cds_hlist_add_head(&event_recorder_priv->hlist, head);
	return 0;

sessiond_register_error:
	free(event_recorder_priv);
priv_error:
	free(event_recorder->parent);
parent_error:
	free(event_recorder);
cache_error:
create_enum_error:
socket_error:
	return ret;
}

static
int lttng_event_notifier_create(const struct lttng_ust_event_desc *desc,
		uint64_t token, uint64_t error_counter_index,
		struct lttng_event_notifier_group *event_notifier_group)
{
	struct lttng_ust_event_notifier *event_notifier;
	struct lttng_ust_event_notifier_private *event_notifier_priv;
	struct cds_hlist_head *head;
	int ret = 0;

	/*
	 * Get the hashtable bucket the created lttng_event_notifier object
	 * should be inserted.
	 */
	head = borrow_hash_table_bucket(
		event_notifier_group->event_notifiers_ht.table,
		LTTNG_UST_EVENT_NOTIFIER_HT_SIZE, desc);

	event_notifier = zmalloc(sizeof(struct lttng_ust_event_notifier));
	if (!event_notifier) {
		ret = -ENOMEM;
		goto error;
	}
	event_notifier->struct_size = sizeof(struct lttng_ust_event_notifier);

	event_notifier->parent = zmalloc(sizeof(struct lttng_ust_event_common));
	if (!event_notifier->parent) {
		ret = -ENOMEM;
		goto parent_error;
	}
	event_notifier->parent->struct_size = sizeof(struct lttng_ust_event_common);
	event_notifier->parent->type = LTTNG_UST_EVENT_TYPE_NOTIFIER;
	event_notifier->parent->child = event_notifier;

	event_notifier_priv = zmalloc(sizeof(struct lttng_ust_event_notifier_private));
	if (!event_notifier_priv) {
		ret = -ENOMEM;
		goto priv_error;
	}
	event_notifier->priv = event_notifier_priv;
	event_notifier_priv->pub = event_notifier;
	event_notifier->parent->priv = &event_notifier_priv->parent;
	event_notifier_priv->parent.pub = event_notifier->parent;

	event_notifier_priv->group = event_notifier_group;
	event_notifier_priv->parent.user_token = token;
	event_notifier_priv->error_counter_index = error_counter_index;

	/* Event notifier will be enabled by enabler sync. */
	event_notifier->parent->run_filter = lttng_ust_interpret_event_filter;
	event_notifier->parent->enabled = 0;
	event_notifier_priv->parent.registered = 0;

	CDS_INIT_LIST_HEAD(&event_notifier->parent->priv->filter_bytecode_runtime_head);
	CDS_INIT_LIST_HEAD(&event_notifier->priv->capture_bytecode_runtime_head);
	CDS_INIT_LIST_HEAD(&event_notifier_priv->parent.enablers_ref_head);
	event_notifier_priv->parent.desc = desc;
	event_notifier->notification_send = lttng_event_notifier_notification_send;

	cds_list_add(&event_notifier_priv->node,
			&event_notifier_group->event_notifiers_head);
	cds_hlist_add_head(&event_notifier_priv->hlist, head);

	return 0;

priv_error:
	free(event_notifier->parent);
parent_error:
	free(event_notifier);
error:
	return ret;
}

static
int lttng_desc_match_star_glob_enabler(const struct lttng_ust_event_desc *desc,
		struct lttng_enabler *enabler)
{
	char name[LTTNG_UST_ABI_SYM_NAME_LEN];
	int loglevel = 0;
	unsigned int has_loglevel = 0;

	lttng_ust_format_event_name(desc, name);
	assert(enabler->format_type == LTTNG_ENABLER_FORMAT_STAR_GLOB);
	if (!strutils_star_glob_match(enabler->event_param.name, SIZE_MAX,
			name, SIZE_MAX))
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
int lttng_desc_match_event_enabler(const struct lttng_ust_event_desc *desc,
		struct lttng_enabler *enabler)
{
	char name[LTTNG_UST_ABI_SYM_NAME_LEN];
	int loglevel = 0;
	unsigned int has_loglevel = 0;

	lttng_ust_format_event_name(desc, name);
	assert(enabler->format_type == LTTNG_ENABLER_FORMAT_EVENT);
	if (strcmp(name, enabler->event_param.name))
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
int lttng_desc_match_enabler(const struct lttng_ust_event_desc *desc,
		struct lttng_enabler *enabler)
{
	switch (enabler->format_type) {
	case LTTNG_ENABLER_FORMAT_STAR_GLOB:
	{
		struct lttng_ust_excluder_node *excluder;

		if (!lttng_desc_match_star_glob_enabler(desc, enabler)) {
			return 0;
		}

		/*
		 * If the matching event matches with an excluder,
		 * return 'does not match'
		 */
		cds_list_for_each_entry(excluder, &enabler->excluder_head, node) {
			int count;

			for (count = 0; count < excluder->excluder.count; count++) {
				int len;
				char *excluder_name;

				excluder_name = (char *) (excluder->excluder.names)
						+ count * LTTNG_UST_ABI_SYM_NAME_LEN;
				len = strnlen(excluder_name, LTTNG_UST_ABI_SYM_NAME_LEN);
				if (len > 0) {
					char name[LTTNG_UST_ABI_SYM_NAME_LEN];

					lttng_ust_format_event_name(desc, name);
					if (strutils_star_glob_match(excluder_name, len, name, SIZE_MAX)) {
						return 0;
					}
				}
			}
		}
		return 1;
	}
	case LTTNG_ENABLER_FORMAT_EVENT:
		return lttng_desc_match_event_enabler(desc, enabler);
	default:
		return -EINVAL;
	}
}

static
int lttng_event_enabler_match_event(struct lttng_event_enabler *event_enabler,
		struct lttng_ust_event_recorder *event_recorder)
{
	if (lttng_desc_match_enabler(event_recorder->parent->priv->desc,
			lttng_event_enabler_as_enabler(event_enabler))
			&& event_recorder->chan == event_enabler->chan)
		return 1;
	else
		return 0;
}

static
int lttng_event_notifier_enabler_match_event_notifier(
		struct lttng_event_notifier_enabler *event_notifier_enabler,
		struct lttng_ust_event_notifier *event_notifier)
{
	int desc_matches = lttng_desc_match_enabler(event_notifier->priv->parent.desc,
		lttng_event_notifier_enabler_as_enabler(event_notifier_enabler));

	if (desc_matches && event_notifier->priv->group == event_notifier_enabler->group &&
			event_notifier->priv->parent.user_token == event_notifier_enabler->user_token)
		return 1;
	else
		return 0;
}

static
struct lttng_enabler_ref *lttng_enabler_ref(
		struct cds_list_head *enabler_ref_list,
		struct lttng_enabler *enabler)
{
	struct lttng_enabler_ref *enabler_ref;

	cds_list_for_each_entry(enabler_ref, enabler_ref_list, node) {
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
void lttng_create_event_recorder_if_missing(struct lttng_event_enabler *event_enabler)
{
	struct lttng_ust_session *session = event_enabler->chan->parent->session;
	struct lttng_ust_registered_probe *reg_probe;
	const struct lttng_ust_event_desc *desc;
	struct lttng_ust_event_recorder_private *event_recorder_priv;
	int i;
	struct cds_list_head *probe_list;

	probe_list = lttng_get_probe_list_head();
	/*
	 * For each probe event, if we find that a probe event matches
	 * our enabler, create an associated lttng_event if not
	 * already present.
	 */
	cds_list_for_each_entry(reg_probe, probe_list, head) {
		const struct lttng_ust_probe_desc *probe_desc = reg_probe->desc;

		for (i = 0; i < probe_desc->nr_events; i++) {
			int ret;
			bool found = false;
			struct cds_hlist_head *head;
			struct cds_hlist_node *node;

			desc = probe_desc->event_desc[i];
			if (!lttng_desc_match_enabler(desc,
					lttng_event_enabler_as_enabler(event_enabler)))
				continue;

			head = borrow_hash_table_bucket(
				session->priv->events_ht.table,
				LTTNG_UST_EVENT_HT_SIZE, desc);

			cds_hlist_for_each_entry(event_recorder_priv, node, head, hlist) {
				if (event_recorder_priv->parent.desc == desc
						&& event_recorder_priv->pub->chan == event_enabler->chan) {
					found = true;
					break;
				}
			}
			if (found)
				continue;

			/*
			 * We need to create an event for this
			 * event probe.
			 */
			ret = lttng_event_recorder_create(probe_desc->event_desc[i],
					event_enabler->chan);
			if (ret) {
				DBG("Unable to create event \"%s:%s\", error %d\n",
					probe_desc->provider_name,
					probe_desc->event_desc[i]->event_name, ret);
			}
		}
	}
}

static
void probe_provider_event_for_each(const struct lttng_ust_probe_desc *provider_desc,
		void (*event_func)(struct lttng_ust_event_common *event))
{
	struct cds_hlist_node *node, *tmp_node;
	struct cds_list_head *sessionsp;
	unsigned int i;

	/* Get handle on list of sessions. */
	sessionsp = lttng_get_sessions();

	/*
	 * Iterate over all events in the probe provider descriptions and
	 * sessions to queue the unregistration of the events.
	 */
	for (i = 0; i < provider_desc->nr_events; i++) {
		const struct lttng_ust_event_desc *event_desc;
		struct lttng_event_notifier_group *event_notifier_group;
		struct lttng_ust_event_recorder_private *event_recorder_priv;
		struct lttng_ust_event_notifier_private *event_notifier_priv;
		struct lttng_ust_session_private *session_priv;
		struct cds_hlist_head *head;

		event_desc = provider_desc->event_desc[i];

		/*
		 * Iterate over all session to find the current event
		 * description.
		 */
		cds_list_for_each_entry(session_priv, sessionsp, node) {
			/*
			 * Get the list of events in the hashtable bucket and
			 * iterate to find the event matching this descriptor.
			 */
			head = borrow_hash_table_bucket(
				session_priv->events_ht.table,
				LTTNG_UST_EVENT_HT_SIZE, event_desc);

			cds_hlist_for_each_entry_safe(event_recorder_priv, node, tmp_node, head, hlist) {
				if (event_desc == event_recorder_priv->parent.desc) {
					event_func(event_recorder_priv->parent.pub);
					break;
				}
			}
		}

		/*
		 * Iterate over all event_notifier groups to find the current event
		 * description.
		 */
		cds_list_for_each_entry(event_notifier_group, &event_notifier_groups, node) {
			/*
			 * Get the list of event_notifiers in the hashtable bucket and
			 * iterate to find the event_notifier matching this
			 * descriptor.
			 */
			head = borrow_hash_table_bucket(
				event_notifier_group->event_notifiers_ht.table,
				LTTNG_UST_EVENT_NOTIFIER_HT_SIZE, event_desc);

			cds_hlist_for_each_entry_safe(event_notifier_priv, node, tmp_node, head, hlist) {
				if (event_desc == event_notifier_priv->parent.desc) {
					event_func(event_notifier_priv->parent.pub);
					break;
				}
			}
		}
	}
}

static
void _event_enum_destroy(struct lttng_ust_event_common *event)
{

	switch (event->type) {
	case LTTNG_UST_EVENT_TYPE_RECORDER:
	{
		struct lttng_ust_event_recorder *event_recorder = event->child;
		struct lttng_ust_session *session = event_recorder->chan->parent->session;
		unsigned int i;

		/* Destroy enums of the current event. */
		for (i = 0; i < event_recorder->parent->priv->desc->nr_fields; i++) {
			const struct lttng_ust_enum_desc *enum_desc;
			const struct lttng_ust_event_field *field;
			struct lttng_enum *curr_enum;

			field = event_recorder->parent->priv->desc->fields[i];
			switch (field->type->type) {
			case lttng_ust_type_enum:
				enum_desc = lttng_ust_get_type_enum(field->type)->desc;
				break;
			default:
				continue;
			}

			curr_enum = lttng_ust_enum_get_from_desc(session, enum_desc);
			if (curr_enum) {
				_lttng_enum_destroy(curr_enum);
			}
		}
		break;
	}
	case LTTNG_UST_EVENT_TYPE_NOTIFIER:
		break;
	default:
		abort();
	}
	/* Destroy event. */
	_lttng_event_destroy(event);
}

/*
 * Iterate over all the UST sessions to unregister and destroy all probes from
 * the probe provider descriptor received as argument. Must me called with the
 * ust_lock held.
 */
void lttng_probe_provider_unregister_events(
		const struct lttng_ust_probe_desc *provider_desc)
{
	/*
	 * Iterate over all events in the probe provider descriptions and sessions
	 * to queue the unregistration of the events.
	 */
	probe_provider_event_for_each(provider_desc, _lttng_event_unregister);

	/* Wait for grace period. */
	lttng_ust_urcu_synchronize_rcu();
	/* Prune the unregistration queue. */
	lttng_ust_tp_probe_prune_release_queue();

	/*
	 * It is now safe to destroy the events and remove them from the event list
	 * and hashtables.
	 */
	probe_provider_event_for_each(provider_desc, _event_enum_destroy);
}

/*
 * Create events associated with an event enabler (if not already present),
 * and add backward reference from the event to the enabler.
 */
static
int lttng_event_enabler_ref_event_recorders(struct lttng_event_enabler *event_enabler)
{
	struct lttng_ust_session *session = event_enabler->chan->parent->session;
	struct lttng_ust_event_recorder_private *event_recorder_priv;

	if (!lttng_event_enabler_as_enabler(event_enabler)->enabled)
		goto end;

	/* First ensure that probe events are created for this enabler. */
	lttng_create_event_recorder_if_missing(event_enabler);

	/* For each event matching enabler in session event list. */
	cds_list_for_each_entry(event_recorder_priv, &session->priv->events_head, node) {
		struct lttng_enabler_ref *enabler_ref;

		if (!lttng_event_enabler_match_event(event_enabler, event_recorder_priv->pub))
			continue;

		enabler_ref = lttng_enabler_ref(&event_recorder_priv->parent.enablers_ref_head,
			lttng_event_enabler_as_enabler(event_enabler));
		if (!enabler_ref) {
			/*
			 * If no backward ref, create it.
			 * Add backward ref from event to enabler.
			 */
			enabler_ref = zmalloc(sizeof(*enabler_ref));
			if (!enabler_ref)
				return -ENOMEM;
			enabler_ref->ref = lttng_event_enabler_as_enabler(
				event_enabler);
			cds_list_add(&enabler_ref->node,
				&event_recorder_priv->parent.enablers_ref_head);
		}

		/*
		 * Link filter bytecodes if not linked yet.
		 */
		lttng_enabler_link_bytecode(event_recorder_priv->parent.desc,
			&session->priv->ctx,
			&event_recorder_priv->parent.filter_bytecode_runtime_head,
			&lttng_event_enabler_as_enabler(event_enabler)->filter_bytecode_head);

		/* TODO: merge event context. */
	}
end:
	return 0;
}

/*
 * Called at library load: connect the probe on all enablers matching
 * this event.
 * Called with session mutex held.
 */
int lttng_fix_pending_events(void)
{
	struct lttng_ust_session_private *session_priv;

	cds_list_for_each_entry(session_priv, &sessions, node) {
		lttng_session_lazy_sync_event_enablers(session_priv->pub);
	}
	return 0;
}

int lttng_fix_pending_event_notifiers(void)
{
	struct lttng_event_notifier_group *event_notifier_group;

	cds_list_for_each_entry(event_notifier_group, &event_notifier_groups, node) {
		lttng_event_notifier_group_sync_enablers(event_notifier_group);
	}
	return 0;
}

/*
 * For each session of the owner thread, execute pending statedump.
 * Only dump state for the sessions owned by the caller thread, because
 * we don't keep ust_lock across the entire iteration.
 */
void lttng_handle_pending_statedump(void *owner)
{
	struct lttng_ust_session_private *session_priv;

	/* Execute state dump */
	do_lttng_ust_statedump(owner);

	/* Clear pending state dump */
	if (ust_lock()) {
		goto end;
	}
	cds_list_for_each_entry(session_priv, &sessions, node) {
		if (session_priv->owner != owner)
			continue;
		if (!session_priv->statedump_pending)
			continue;
		session_priv->statedump_pending = 0;
	}
end:
	ust_unlock();
	return;
}

static
void _lttng_event_destroy(struct lttng_ust_event_common *event)
{
	struct lttng_enabler_ref *enabler_ref, *tmp_enabler_ref;

	lttng_free_event_filter_runtime(event);
	/* Free event enabler refs */
	cds_list_for_each_entry_safe(enabler_ref, tmp_enabler_ref,
			&event->priv->enablers_ref_head, node)
		free(enabler_ref);

	switch (event->type) {
	case LTTNG_UST_EVENT_TYPE_RECORDER:
	{
		struct lttng_ust_event_recorder *event_recorder = event->child;

		/* Remove from event list. */
		cds_list_del(&event_recorder->priv->node);
		/* Remove from event hash table. */
		cds_hlist_del(&event_recorder->priv->hlist);

		lttng_destroy_context(event_recorder->priv->ctx);
		free(event_recorder->parent);
		free(event_recorder->priv);
		free(event_recorder);
		break;
	}
	case LTTNG_UST_EVENT_TYPE_NOTIFIER:
	{
		struct lttng_ust_event_notifier *event_notifier = event->child;

		/* Remove from event list. */
		cds_list_del(&event_notifier->priv->node);
		/* Remove from event hash table. */
		cds_hlist_del(&event_notifier->priv->hlist);

		free(event_notifier->priv);
		free(event_notifier->parent);
		free(event_notifier);
		break;
	}
	default:
		abort();
	}
}

static
void _lttng_enum_destroy(struct lttng_enum *_enum)
{
	cds_list_del(&_enum->node);
	cds_hlist_del(&_enum->hlist);
	free(_enum);
}

void lttng_ust_abi_events_exit(void)
{
	struct lttng_ust_session_private *session_priv, *tmpsession_priv;

	cds_list_for_each_entry_safe(session_priv, tmpsession_priv, &sessions, node)
		lttng_session_destroy(session_priv->pub);
}

/*
 * Enabler management.
 */
struct lttng_event_enabler *lttng_event_enabler_create(
		enum lttng_enabler_format_type format_type,
		struct lttng_ust_abi_event *event_param,
		struct lttng_ust_channel_buffer *chan)
{
	struct lttng_event_enabler *event_enabler;

	event_enabler = zmalloc(sizeof(*event_enabler));
	if (!event_enabler)
		return NULL;
	event_enabler->base.format_type = format_type;
	CDS_INIT_LIST_HEAD(&event_enabler->base.filter_bytecode_head);
	CDS_INIT_LIST_HEAD(&event_enabler->base.excluder_head);
	memcpy(&event_enabler->base.event_param, event_param,
		sizeof(event_enabler->base.event_param));
	event_enabler->chan = chan;
	/* ctx left NULL */
	event_enabler->base.enabled = 0;
	cds_list_add(&event_enabler->node, &event_enabler->chan->parent->session->priv->enablers_head);
	lttng_session_lazy_sync_event_enablers(event_enabler->chan->parent->session);

	return event_enabler;
}

struct lttng_event_notifier_enabler *lttng_event_notifier_enabler_create(
		struct lttng_event_notifier_group *event_notifier_group,
		enum lttng_enabler_format_type format_type,
		struct lttng_ust_abi_event_notifier *event_notifier_param)
{
	struct lttng_event_notifier_enabler *event_notifier_enabler;

	event_notifier_enabler = zmalloc(sizeof(*event_notifier_enabler));
	if (!event_notifier_enabler)
		return NULL;
	event_notifier_enabler->base.format_type = format_type;
	CDS_INIT_LIST_HEAD(&event_notifier_enabler->base.filter_bytecode_head);
	CDS_INIT_LIST_HEAD(&event_notifier_enabler->capture_bytecode_head);
	CDS_INIT_LIST_HEAD(&event_notifier_enabler->base.excluder_head);

	event_notifier_enabler->user_token = event_notifier_param->event.token;
	event_notifier_enabler->error_counter_index = event_notifier_param->error_counter_index;
	event_notifier_enabler->num_captures = 0;

	memcpy(&event_notifier_enabler->base.event_param.name,
		event_notifier_param->event.name,
		sizeof(event_notifier_enabler->base.event_param.name));
	event_notifier_enabler->base.event_param.instrumentation =
		event_notifier_param->event.instrumentation;
	event_notifier_enabler->base.event_param.loglevel =
		event_notifier_param->event.loglevel;
	event_notifier_enabler->base.event_param.loglevel_type =
		event_notifier_param->event.loglevel_type;

	event_notifier_enabler->base.enabled = 0;
	event_notifier_enabler->group = event_notifier_group;

	cds_list_add(&event_notifier_enabler->node,
			&event_notifier_group->enablers_head);

	lttng_event_notifier_group_sync_enablers(event_notifier_group);

	return event_notifier_enabler;
}

int lttng_event_enabler_enable(struct lttng_event_enabler *event_enabler)
{
	lttng_event_enabler_as_enabler(event_enabler)->enabled = 1;
	lttng_session_lazy_sync_event_enablers(event_enabler->chan->parent->session);

	return 0;
}

int lttng_event_enabler_disable(struct lttng_event_enabler *event_enabler)
{
	lttng_event_enabler_as_enabler(event_enabler)->enabled = 0;
	lttng_session_lazy_sync_event_enablers(event_enabler->chan->parent->session);

	return 0;
}

static
void _lttng_enabler_attach_filter_bytecode(struct lttng_enabler *enabler,
		struct lttng_ust_bytecode_node **bytecode)
{
	(*bytecode)->enabler = enabler;
	cds_list_add_tail(&(*bytecode)->node, &enabler->filter_bytecode_head);
	/* Take ownership of bytecode */
	*bytecode = NULL;
}

int lttng_event_enabler_attach_filter_bytecode(struct lttng_event_enabler *event_enabler,
		struct lttng_ust_bytecode_node **bytecode)
{
	_lttng_enabler_attach_filter_bytecode(
		lttng_event_enabler_as_enabler(event_enabler), bytecode);

	lttng_session_lazy_sync_event_enablers(event_enabler->chan->parent->session);
	return 0;
}

static
void _lttng_enabler_attach_exclusion(struct lttng_enabler *enabler,
		struct lttng_ust_excluder_node **excluder)
{
	(*excluder)->enabler = enabler;
	cds_list_add_tail(&(*excluder)->node, &enabler->excluder_head);
	/* Take ownership of excluder */
	*excluder = NULL;
}

int lttng_event_enabler_attach_exclusion(struct lttng_event_enabler *event_enabler,
		struct lttng_ust_excluder_node **excluder)
{
	_lttng_enabler_attach_exclusion(
		lttng_event_enabler_as_enabler(event_enabler), excluder);

	lttng_session_lazy_sync_event_enablers(event_enabler->chan->parent->session);
	return 0;
}

int lttng_event_notifier_enabler_enable(
		struct lttng_event_notifier_enabler *event_notifier_enabler)
{
	lttng_event_notifier_enabler_as_enabler(event_notifier_enabler)->enabled = 1;
	lttng_event_notifier_group_sync_enablers(event_notifier_enabler->group);

	return 0;
}

int lttng_event_notifier_enabler_disable(
		struct lttng_event_notifier_enabler *event_notifier_enabler)
{
	lttng_event_notifier_enabler_as_enabler(event_notifier_enabler)->enabled = 0;
	lttng_event_notifier_group_sync_enablers(event_notifier_enabler->group);

	return 0;
}

int lttng_event_notifier_enabler_attach_filter_bytecode(
		struct lttng_event_notifier_enabler *event_notifier_enabler,
		struct lttng_ust_bytecode_node **bytecode)
{
	_lttng_enabler_attach_filter_bytecode(
		lttng_event_notifier_enabler_as_enabler(event_notifier_enabler),
		bytecode);

	lttng_event_notifier_group_sync_enablers(event_notifier_enabler->group);
	return 0;
}

int lttng_event_notifier_enabler_attach_capture_bytecode(
		struct lttng_event_notifier_enabler *event_notifier_enabler,
		struct lttng_ust_bytecode_node **bytecode)
{
	(*bytecode)->enabler = lttng_event_notifier_enabler_as_enabler(
			event_notifier_enabler);
	cds_list_add_tail(&(*bytecode)->node,
			&event_notifier_enabler->capture_bytecode_head);
	/* Take ownership of bytecode */
	*bytecode = NULL;
	event_notifier_enabler->num_captures++;

	lttng_event_notifier_group_sync_enablers(event_notifier_enabler->group);
	return 0;
}

int lttng_event_notifier_enabler_attach_exclusion(
		struct lttng_event_notifier_enabler *event_notifier_enabler,
		struct lttng_ust_excluder_node **excluder)
{
	_lttng_enabler_attach_exclusion(
		lttng_event_notifier_enabler_as_enabler(event_notifier_enabler),
		excluder);

	lttng_event_notifier_group_sync_enablers(event_notifier_enabler->group);
	return 0;
}

int lttng_attach_context(struct lttng_ust_abi_context *context_param,
		union lttng_ust_abi_args *uargs,
		struct lttng_ust_ctx **ctx, struct lttng_ust_session *session)
{
	/*
	 * We cannot attach a context after trace has been started for a
	 * session because the metadata does not allow expressing this
	 * information outside of the original channel scope.
	 */
	if (session->priv->been_active)
		return -EPERM;

	switch (context_param->ctx) {
	case LTTNG_UST_ABI_CONTEXT_PTHREAD_ID:
		return lttng_add_pthread_id_to_ctx(ctx);
	case LTTNG_UST_ABI_CONTEXT_PERF_THREAD_COUNTER:
	{
		struct lttng_ust_abi_perf_counter_ctx *perf_ctx_param;

		perf_ctx_param = &context_param->u.perf_counter;
		return lttng_add_perf_counter_to_ctx(
			perf_ctx_param->type,
			perf_ctx_param->config,
			perf_ctx_param->name,
			ctx);
	}
	case LTTNG_UST_ABI_CONTEXT_VTID:
		return lttng_add_vtid_to_ctx(ctx);
	case LTTNG_UST_ABI_CONTEXT_VPID:
		return lttng_add_vpid_to_ctx(ctx);
	case LTTNG_UST_ABI_CONTEXT_PROCNAME:
		return lttng_add_procname_to_ctx(ctx);
	case LTTNG_UST_ABI_CONTEXT_IP:
		return lttng_add_ip_to_ctx(ctx);
	case LTTNG_UST_ABI_CONTEXT_CPU_ID:
		return lttng_add_cpu_id_to_ctx(ctx);
	case LTTNG_UST_ABI_CONTEXT_APP_CONTEXT:
		return lttng_ust_add_app_context_to_ctx_rcu(uargs->app_context.ctxname,
			ctx);
	case LTTNG_UST_ABI_CONTEXT_CGROUP_NS:
		return lttng_add_cgroup_ns_to_ctx(ctx);
	case LTTNG_UST_ABI_CONTEXT_IPC_NS:
		return lttng_add_ipc_ns_to_ctx(ctx);
	case LTTNG_UST_ABI_CONTEXT_MNT_NS:
		return lttng_add_mnt_ns_to_ctx(ctx);
	case LTTNG_UST_ABI_CONTEXT_NET_NS:
		return lttng_add_net_ns_to_ctx(ctx);
	case LTTNG_UST_ABI_CONTEXT_PID_NS:
		return lttng_add_pid_ns_to_ctx(ctx);
	case LTTNG_UST_ABI_CONTEXT_TIME_NS:
		return lttng_add_time_ns_to_ctx(ctx);
	case LTTNG_UST_ABI_CONTEXT_USER_NS:
		return lttng_add_user_ns_to_ctx(ctx);
	case LTTNG_UST_ABI_CONTEXT_UTS_NS:
		return lttng_add_uts_ns_to_ctx(ctx);
	case LTTNG_UST_ABI_CONTEXT_VUID:
		return lttng_add_vuid_to_ctx(ctx);
	case LTTNG_UST_ABI_CONTEXT_VEUID:
		return lttng_add_veuid_to_ctx(ctx);
	case LTTNG_UST_ABI_CONTEXT_VSUID:
		return lttng_add_vsuid_to_ctx(ctx);
	case LTTNG_UST_ABI_CONTEXT_VGID:
		return lttng_add_vgid_to_ctx(ctx);
	case LTTNG_UST_ABI_CONTEXT_VEGID:
		return lttng_add_vegid_to_ctx(ctx);
	case LTTNG_UST_ABI_CONTEXT_VSGID:
		return lttng_add_vsgid_to_ctx(ctx);
	default:
		return -EINVAL;
	}
}

int lttng_event_enabler_attach_context(
		struct lttng_event_enabler *enabler __attribute__((unused)),
		struct lttng_ust_abi_context *context_param __attribute__((unused)))
{
	return -ENOSYS;
}

void lttng_event_enabler_destroy(struct lttng_event_enabler *event_enabler)
{
	if (!event_enabler) {
		return;
	}
	cds_list_del(&event_enabler->node);

	lttng_enabler_destroy(lttng_event_enabler_as_enabler(event_enabler));

	lttng_destroy_context(event_enabler->ctx);
	free(event_enabler);
}

/*
 * lttng_session_sync_event_enablers should be called just before starting a
 * session.
 */
static
void lttng_session_sync_event_enablers(struct lttng_ust_session *session)
{
	struct lttng_event_enabler *event_enabler;
	struct lttng_ust_event_recorder_private *event_recorder_priv;

	cds_list_for_each_entry(event_enabler, &session->priv->enablers_head, node)
		lttng_event_enabler_ref_event_recorders(event_enabler);
	/*
	 * For each event, if at least one of its enablers is enabled,
	 * and its channel and session transient states are enabled, we
	 * enable the event, else we disable it.
	 */
	cds_list_for_each_entry(event_recorder_priv, &session->priv->events_head, node) {
		struct lttng_enabler_ref *enabler_ref;
		struct lttng_ust_bytecode_runtime *runtime;
		int enabled = 0, has_enablers_without_filter_bytecode = 0;
		int nr_filters = 0;

		/* Enable events */
		cds_list_for_each_entry(enabler_ref,
				&event_recorder_priv->parent.enablers_ref_head, node) {
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
		enabled = enabled && session->priv->tstate && event_recorder_priv->pub->chan->priv->parent.tstate;

		CMM_STORE_SHARED(event_recorder_priv->pub->parent->enabled, enabled);
		/*
		 * Sync tracepoint registration with event enabled
		 * state.
		 */
		if (enabled) {
			if (!event_recorder_priv->parent.registered)
				register_event(event_recorder_priv->parent.pub);
		} else {
			if (event_recorder_priv->parent.registered)
				unregister_event(event_recorder_priv->parent.pub);
		}

		/* Check if has enablers without bytecode enabled */
		cds_list_for_each_entry(enabler_ref,
				&event_recorder_priv->parent.enablers_ref_head, node) {
			if (enabler_ref->ref->enabled
					&& cds_list_empty(&enabler_ref->ref->filter_bytecode_head)) {
				has_enablers_without_filter_bytecode = 1;
				break;
			}
		}
		event_recorder_priv->parent.has_enablers_without_filter_bytecode =
			has_enablers_without_filter_bytecode;

		/* Enable filters */
		cds_list_for_each_entry(runtime,
				&event_recorder_priv->parent.filter_bytecode_runtime_head, node) {
			lttng_bytecode_sync_state(runtime);
			nr_filters++;
		}
		CMM_STORE_SHARED(event_recorder_priv->parent.pub->eval_filter,
			!(has_enablers_without_filter_bytecode || !nr_filters));
	}
	lttng_ust_tp_probe_prune_release_queue();
}

/* Support for event notifier is introduced by probe provider major version 2. */
static
bool lttng_ust_probe_supports_event_notifier(const struct lttng_ust_probe_desc *probe_desc)
{
	return probe_desc->major >= 2;
}

static
void lttng_create_event_notifier_if_missing(
		struct lttng_event_notifier_enabler *event_notifier_enabler)
{
	struct lttng_event_notifier_group *event_notifier_group = event_notifier_enabler->group;
	struct lttng_ust_registered_probe *reg_probe;
	struct cds_list_head *probe_list;
	int i;

	probe_list = lttng_get_probe_list_head();

	cds_list_for_each_entry(reg_probe, probe_list, head) {
		const struct lttng_ust_probe_desc *probe_desc = reg_probe->desc;

		for (i = 0; i < probe_desc->nr_events; i++) {
			int ret;
			bool found = false;
			const struct lttng_ust_event_desc *desc;
			struct lttng_ust_event_notifier_private *event_notifier_priv;
			struct cds_hlist_head *head;
			struct cds_hlist_node *node;

			desc = probe_desc->event_desc[i];

			if (!lttng_desc_match_enabler(desc,
					lttng_event_notifier_enabler_as_enabler(event_notifier_enabler)))
				continue;

			/*
			 * Given the current event_notifier group, get the bucket that
			 * the target event_notifier would be if it was already
			 * created.
			 */
			head = borrow_hash_table_bucket(
				event_notifier_group->event_notifiers_ht.table,
				LTTNG_UST_EVENT_NOTIFIER_HT_SIZE, desc);

			cds_hlist_for_each_entry(event_notifier_priv, node, head, hlist) {
				/*
				 * Check if event_notifier already exists by checking
				 * if the event_notifier and enabler share the same
				 * description and id.
				 */
				if (event_notifier_priv->parent.desc == desc &&
						event_notifier_priv->parent.user_token == event_notifier_enabler->user_token) {
					found = true;
					break;
				}
			}

			if (found)
				continue;

			/* Check that the probe supports event notifiers, else report the error. */
			if (!lttng_ust_probe_supports_event_notifier(probe_desc)) {
				ERR("Probe \"%s\" contains event \"%s:%s\" which matches an enabled event notifier, "
					"but its version (%u.%u) is too old and does not implement event notifiers. "
					"It needs to be recompiled against a newer version of LTTng-UST, otherwise "
					"this event will not generate any notification.",
					probe_desc->provider_name,
					probe_desc->provider_name, desc->event_name,
					probe_desc->major,
					probe_desc->minor);
				continue;
			}
			/*
			 * We need to create a event_notifier for this event probe.
			 */
			ret = lttng_event_notifier_create(desc,
				event_notifier_enabler->user_token,
				event_notifier_enabler->error_counter_index,
				event_notifier_group);
			if (ret) {
				DBG("Unable to create event_notifier \"%s:%s\", error %d\n",
					probe_desc->provider_name,
					probe_desc->event_desc[i]->event_name, ret);
			}
		}
	}
}

/*
 * Create event_notifiers associated with a event_notifier enabler (if not already present).
 */
static
int lttng_event_notifier_enabler_ref_event_notifiers(
		struct lttng_event_notifier_enabler *event_notifier_enabler)
{
	struct lttng_event_notifier_group *event_notifier_group = event_notifier_enabler->group;
	struct lttng_ust_event_notifier_private *event_notifier_priv;

	 /*
	  * Only try to create event_notifiers for enablers that are enabled, the user
	  * might still be attaching filter or exclusion to the
	  * event_notifier_enabler.
	  */
	if (!lttng_event_notifier_enabler_as_enabler(event_notifier_enabler)->enabled)
		goto end;

	/* First, ensure that probe event_notifiers are created for this enabler. */
	lttng_create_event_notifier_if_missing(event_notifier_enabler);

	/* Link the created event_notifier with its associated enabler. */
	cds_list_for_each_entry(event_notifier_priv, &event_notifier_group->event_notifiers_head, node) {
		struct lttng_enabler_ref *enabler_ref;

		if (!lttng_event_notifier_enabler_match_event_notifier(event_notifier_enabler, event_notifier_priv->pub))
			continue;

		enabler_ref = lttng_enabler_ref(&event_notifier_priv->parent.enablers_ref_head,
			lttng_event_notifier_enabler_as_enabler(event_notifier_enabler));
		if (!enabler_ref) {
			/*
			 * If no backward ref, create it.
			 * Add backward ref from event_notifier to enabler.
			 */
			enabler_ref = zmalloc(sizeof(*enabler_ref));
			if (!enabler_ref)
				return -ENOMEM;

			enabler_ref->ref = lttng_event_notifier_enabler_as_enabler(
				event_notifier_enabler);
			cds_list_add(&enabler_ref->node,
				&event_notifier_priv->parent.enablers_ref_head);
		}

		/*
		 * Link filter bytecodes if not linked yet.
		 */
		lttng_enabler_link_bytecode(event_notifier_priv->parent.desc,
			&event_notifier_group->ctx,
			&event_notifier_priv->parent.filter_bytecode_runtime_head,
			&lttng_event_notifier_enabler_as_enabler(event_notifier_enabler)->filter_bytecode_head);

		/*
		 * Link capture bytecodes if not linked yet.
		 */
		lttng_enabler_link_bytecode(event_notifier_priv->parent.desc,
			&event_notifier_group->ctx, &event_notifier_priv->capture_bytecode_runtime_head,
			&event_notifier_enabler->capture_bytecode_head);

		event_notifier_priv->num_captures = event_notifier_enabler->num_captures;
	}
end:
	return 0;
}

static
void lttng_event_notifier_group_sync_enablers(struct lttng_event_notifier_group *event_notifier_group)
{
	struct lttng_event_notifier_enabler *event_notifier_enabler;
	struct lttng_ust_event_notifier_private *event_notifier_priv;

	cds_list_for_each_entry(event_notifier_enabler, &event_notifier_group->enablers_head, node)
		lttng_event_notifier_enabler_ref_event_notifiers(event_notifier_enabler);

	/*
	 * For each event_notifier, if at least one of its enablers is enabled,
	 * we enable the event_notifier, else we disable it.
	 */
	cds_list_for_each_entry(event_notifier_priv, &event_notifier_group->event_notifiers_head, node) {
		struct lttng_enabler_ref *enabler_ref;
		struct lttng_ust_bytecode_runtime *runtime;
		int enabled = 0, has_enablers_without_filter_bytecode = 0;
		int nr_filters = 0, nr_captures = 0;

		/* Enable event_notifiers */
		cds_list_for_each_entry(enabler_ref,
				&event_notifier_priv->parent.enablers_ref_head, node) {
			if (enabler_ref->ref->enabled) {
				enabled = 1;
				break;
			}
		}

		CMM_STORE_SHARED(event_notifier_priv->pub->parent->enabled, enabled);
		/*
		 * Sync tracepoint registration with event_notifier enabled
		 * state.
		 */
		if (enabled) {
			if (!event_notifier_priv->parent.registered)
				register_event(event_notifier_priv->parent.pub);
		} else {
			if (event_notifier_priv->parent.registered)
				unregister_event(event_notifier_priv->parent.pub);
		}

		/* Check if has enablers without bytecode enabled */
		cds_list_for_each_entry(enabler_ref,
				&event_notifier_priv->parent.enablers_ref_head, node) {
			if (enabler_ref->ref->enabled
					&& cds_list_empty(&enabler_ref->ref->filter_bytecode_head)) {
				has_enablers_without_filter_bytecode = 1;
				break;
			}
		}
		event_notifier_priv->parent.has_enablers_without_filter_bytecode =
			has_enablers_without_filter_bytecode;

		/* Enable filters */
		cds_list_for_each_entry(runtime,
				&event_notifier_priv->parent.filter_bytecode_runtime_head, node) {
			lttng_bytecode_sync_state(runtime);
			nr_filters++;
		}
		CMM_STORE_SHARED(event_notifier_priv->parent.pub->eval_filter,
			!(has_enablers_without_filter_bytecode || !nr_filters));

		/* Enable captures. */
		cds_list_for_each_entry(runtime,
				&event_notifier_priv->capture_bytecode_runtime_head, node) {
			lttng_bytecode_sync_state(runtime);
			nr_captures++;
		}
		CMM_STORE_SHARED(event_notifier_priv->pub->eval_capture,
				!!nr_captures);
	}
	lttng_ust_tp_probe_prune_release_queue();
}

/*
 * Apply enablers to session events, adding events to session if need
 * be. It is required after each modification applied to an active
 * session, and right before session "start".
 * "lazy" sync means we only sync if required.
 */
static
void lttng_session_lazy_sync_event_enablers(struct lttng_ust_session *session)
{
	/* We can skip if session is not active */
	if (!session->active)
		return;
	lttng_session_sync_event_enablers(session);
}

/*
 * Update all sessions with the given app context.
 * Called with ust lock held.
 * This is invoked when an application context gets loaded/unloaded. It
 * ensures the context callbacks are in sync with the application
 * context (either app context callbacks, or dummy callbacks).
 */
void lttng_ust_context_set_session_provider(const char *name,
		size_t (*get_size)(void *priv, size_t offset),
		void (*record)(void *priv, struct lttng_ust_ring_buffer_ctx *ctx,
			struct lttng_ust_channel_buffer *chan),
		void (*get_value)(void *priv, struct lttng_ust_ctx_value *value),
		void *priv)
{
	struct lttng_ust_session_private *session_priv;

	cds_list_for_each_entry(session_priv, &sessions, node) {
		struct lttng_ust_channel_buffer_private *chan;
		struct lttng_ust_event_recorder_private *event_recorder_priv;
		int ret;

		ret = lttng_ust_context_set_provider_rcu(&session_priv->ctx,
				name, get_size, record, get_value, priv);
		if (ret)
			abort();
		cds_list_for_each_entry(chan, &session_priv->chan_head, node) {
			ret = lttng_ust_context_set_provider_rcu(&chan->ctx,
					name, get_size, record, get_value, priv);
			if (ret)
				abort();
		}
		cds_list_for_each_entry(event_recorder_priv, &session_priv->events_head, node) {
			ret = lttng_ust_context_set_provider_rcu(&event_recorder_priv->ctx,
					name, get_size, record, get_value, priv);
			if (ret)
				abort();
		}
	}
}

/*
 * Update all event_notifier groups with the given app context.
 * Called with ust lock held.
 * This is invoked when an application context gets loaded/unloaded. It
 * ensures the context callbacks are in sync with the application
 * context (either app context callbacks, or dummy callbacks).
 */
void lttng_ust_context_set_event_notifier_group_provider(const char *name,
		size_t (*get_size)(void *priv, size_t offset),
		void (*record)(void *priv, struct lttng_ust_ring_buffer_ctx *ctx,
			struct lttng_ust_channel_buffer *chan),
		void (*get_value)(void *priv, struct lttng_ust_ctx_value *value),
		void *priv)
{
	struct lttng_event_notifier_group *event_notifier_group;

	cds_list_for_each_entry(event_notifier_group, &event_notifier_groups, node) {
		int ret;

		ret = lttng_ust_context_set_provider_rcu(
				&event_notifier_group->ctx,
				name, get_size, record, get_value, priv);
		if (ret)
			abort();
	}
}

int lttng_ust_session_uuid_validate(struct lttng_ust_session *session,
		unsigned char *uuid)
{
	if (!session)
		return 0;
	/* Compare UUID with session. */
	if (session->priv->uuid_set) {
		if (memcmp(session->priv->uuid, uuid, LTTNG_UST_UUID_LEN)) {
			return -1;
		}
	} else {
		memcpy(session->priv->uuid, uuid, LTTNG_UST_UUID_LEN);
		session->priv->uuid_set = true;
	}
	return 0;

}
