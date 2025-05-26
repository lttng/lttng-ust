/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2010-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng UST ABI
 *
 * Mimic system calls for:
 * - session creation, returns an object descriptor or failure.
 *   - channel creation, returns an object descriptor or failure.
 *     - Operates on a session object descriptor
 *     - Takes all channel options as parameters.
 *   - stream get, returns an object descriptor or failure.
 *     - Operates on a channel object descriptor.
 *   - stream notifier get, returns an object descriptor or failure.
 *     - Operates on a channel object descriptor.
 *   - event creation, returns an object descriptor or failure.
 *     - Operates on a channel object descriptor
 *     - Takes an event name as parameter
 *     - Takes an instrumentation source as parameter
 *       - e.g. tracepoints, dynamic_probes...
 *     - Takes instrumentation source specific arguments.
 */

#define _LGPL_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>

#include <urcu/compiler.h>
#include <urcu/list.h>

#include <lttng/tracepoint.h>
#include <lttng/ust-abi.h>
#include <lttng/ust-error.h>
#include <lttng/ust-events.h>
#include <lttng/ust-version.h>
#include <lttng/ust-fd.h>

#include "common/logging.h"
#include "common/align.h"

#include "common/ringbuffer/frontend_types.h"
#include "common/ringbuffer/frontend.h"
#include "common/ringbuffer/shm.h"
#include "common/counter/counter.h"
#include "common/tracepoint.h"
#include "common/tracer.h"
#include "common/strutils.h"
#include "lib/lttng-ust/events.h"
#include "lib/lttng-ust/lttng-tracer-core.h"
#include "context-internal.h"
#include "common/macros.h"

#define OBJ_NAME_LEN	16

static int lttng_ust_abi_close_in_progress;

static
int lttng_abi_tracepoint_list(void *owner);
static
int lttng_abi_tracepoint_field_list(void *owner);

/*
 * Object descriptor table. Should be protected from concurrent access
 * by the caller.
 */

struct lttng_ust_abi_obj {
	union {
		struct {
			void *private_data;
			const struct lttng_ust_abi_objd_ops *ops;
			int f_count;
			int owner_ref;	/* has ref from owner */
			void *owner;
			char name[OBJ_NAME_LEN];
		} s;
		int freelist_next;	/* offset freelist. end is -1. */
	} u;
};

struct lttng_ust_abi_objd_table {
	struct lttng_ust_abi_obj *array;
	unsigned int len, allocated_len;
	int freelist_head;		/* offset freelist head. end is -1 */
};

static struct lttng_ust_abi_objd_table objd_table = {
	.freelist_head = -1,
};

static
int objd_alloc(void *private_data, const struct lttng_ust_abi_objd_ops *ops,
		void *owner, const char *name)
{
	struct lttng_ust_abi_obj *obj;

	if (objd_table.freelist_head != -1) {
		obj = &objd_table.array[objd_table.freelist_head];
		objd_table.freelist_head = obj->u.freelist_next;
		goto end;
	}

	if (objd_table.len >= objd_table.allocated_len) {
		unsigned int new_allocated_len, old_allocated_len;
		struct lttng_ust_abi_obj *new_table, *old_table;

		old_allocated_len = objd_table.allocated_len;
		old_table = objd_table.array;
		if (!old_allocated_len)
			new_allocated_len = 1;
		else
			new_allocated_len = old_allocated_len << 1;
		new_table = zmalloc(sizeof(struct lttng_ust_abi_obj) * new_allocated_len);
		if (!new_table)
			return -ENOMEM;
		memcpy(new_table, old_table,
		       sizeof(struct lttng_ust_abi_obj) * old_allocated_len);
		free(old_table);
		objd_table.array = new_table;
		objd_table.allocated_len = new_allocated_len;
	}
	obj = &objd_table.array[objd_table.len];
	objd_table.len++;
end:
	obj->u.s.private_data = private_data;
	obj->u.s.ops = ops;
	obj->u.s.f_count = 2;	/* count == 1 : object is allocated */
				/* count == 2 : allocated + hold ref */
	obj->u.s.owner_ref = 1;	/* One owner reference */
	obj->u.s.owner = owner;
	strncpy(obj->u.s.name, name, OBJ_NAME_LEN);
	obj->u.s.name[OBJ_NAME_LEN - 1] = '\0';
	return obj - objd_table.array;
}

static
struct lttng_ust_abi_obj *_objd_get(int id)
{
	if (id >= objd_table.len)
		return NULL;
	if (!objd_table.array[id].u.s.f_count)
		return NULL;
	return &objd_table.array[id];
}

static
void *objd_private(int id)
{
	struct lttng_ust_abi_obj *obj = _objd_get(id);
	assert(obj);
	return obj->u.s.private_data;
}

static
void objd_set_private(int id, void *private_data)
{
	struct lttng_ust_abi_obj *obj = _objd_get(id);
	assert(obj);
	obj->u.s.private_data = private_data;
}

const struct lttng_ust_abi_objd_ops *lttng_ust_abi_objd_ops(int id)
{
	struct lttng_ust_abi_obj *obj = _objd_get(id);

	if (!obj)
		return NULL;
	return obj->u.s.ops;
}

static
void objd_free(int id)
{
	struct lttng_ust_abi_obj *obj = _objd_get(id);

	assert(obj);
	obj->u.freelist_next = objd_table.freelist_head;
	objd_table.freelist_head = obj - objd_table.array;
	assert(obj->u.s.f_count == 1);
	obj->u.s.f_count = 0;	/* deallocated */
}

static
void objd_ref(int id)
{
	struct lttng_ust_abi_obj *obj = _objd_get(id);
	assert(obj != NULL);
	obj->u.s.f_count++;
}

int lttng_ust_abi_objd_unref(int id, int is_owner)
{
	struct lttng_ust_abi_obj *obj = _objd_get(id);

	if (!obj)
		return -EINVAL;
	if (obj->u.s.f_count == 1) {
		ERR("Reference counting error\n");
		return -EINVAL;
	}
	if (is_owner) {
		if (!obj->u.s.owner_ref) {
			ERR("Error decrementing owner reference");
			return -EINVAL;
		}
		obj->u.s.owner_ref--;
	}
	if ((--obj->u.s.f_count) == 1) {
		const struct lttng_ust_abi_objd_ops *ops = lttng_ust_abi_objd_ops(id);

		if (ops->release)
			ops->release(id);
		objd_free(id);
	}
	return 0;
}

static
void objd_table_destroy(void)
{
	int i;

	for (i = 0; i < objd_table.allocated_len; i++) {
		struct lttng_ust_abi_obj *obj;

		obj = _objd_get(i);
		if (!obj)
			continue;
		if (!obj->u.s.owner_ref)
			continue;	/* only unref owner ref. */
		(void) lttng_ust_abi_objd_unref(i, 1);
	}
	free(objd_table.array);
	objd_table.array = NULL;
	objd_table.len = 0;
	objd_table.allocated_len = 0;
	objd_table.freelist_head = -1;
}

const char *lttng_ust_obj_get_name(int id)
{
	struct lttng_ust_abi_obj *obj = _objd_get(id);

	if (!obj)
		return NULL;
	return obj->u.s.name;
}

void lttng_ust_abi_objd_table_owner_cleanup(void *owner)
{
	int i;

	for (i = 0; i < objd_table.allocated_len; i++) {
		struct lttng_ust_abi_obj *obj;

		obj = _objd_get(i);
		if (!obj)
			continue;
		if (!obj->u.s.owner)
			continue;	/* skip root handles */
		if (!obj->u.s.owner_ref)
			continue;	/* only unref owner ref. */
		if (obj->u.s.owner == owner)
			(void) lttng_ust_abi_objd_unref(i, 1);
	}
}

/*
 * This is LTTng's own personal way to create an ABI for sessiond.
 * We send commands over a socket.
 */

static const struct lttng_ust_abi_objd_ops lttng_ops;
static const struct lttng_ust_abi_objd_ops lttng_event_notifier_group_ops;
static const struct lttng_ust_abi_objd_ops lttng_session_ops;
static const struct lttng_ust_abi_objd_ops lttng_channel_ops;
static const struct lttng_ust_abi_objd_ops lttng_counter_ops;
static const struct lttng_ust_abi_objd_ops lttng_event_enabler_ops;
static const struct lttng_ust_abi_objd_ops lttng_event_notifier_enabler_ops;
static const struct lttng_ust_abi_objd_ops lttng_tracepoint_list_ops;
static const struct lttng_ust_abi_objd_ops lttng_tracepoint_field_list_ops;

int lttng_abi_create_root_handle(void)
{
	int root_handle;

	/* root handles have NULL owners */
	root_handle = objd_alloc(NULL, &lttng_ops, NULL, "root");
	return root_handle;
}

static
int lttng_is_channel_ready(struct lttng_ust_channel_buffer *lttng_chan)
{
	struct lttng_ust_ring_buffer_channel *chan;
	unsigned int nr_streams, exp_streams;

	chan = lttng_chan->priv->rb_chan;
	nr_streams = channel_handle_get_nr_streams(lttng_chan->priv->rb_chan->handle);
	exp_streams = chan->nr_streams;
	return nr_streams == exp_streams;
}

static
int lttng_abi_create_session(void *owner)
{
	struct lttng_ust_session *session;
	int session_objd, ret;

	session = lttng_session_create();
	if (!session)
		return -ENOMEM;
	session_objd = objd_alloc(session, &lttng_session_ops, owner, "session");
	if (session_objd < 0) {
		ret = session_objd;
		goto objd_error;
	}
	session->priv->objd = session_objd;
	session->priv->owner = owner;
	return session_objd;

objd_error:
	lttng_session_destroy(session);
	return ret;
}

static
long lttng_abi_tracer_version(int objd __attribute__((unused)),
	struct lttng_ust_abi_tracer_version *v)
{
	v->major = LTTNG_UST_MAJOR_VERSION;
	v->minor = LTTNG_UST_MINOR_VERSION;
	v->patchlevel = LTTNG_UST_PATCHLEVEL_VERSION;
	return 0;
}

static
int lttng_abi_event_notifier_send_fd(void *owner, int *event_notifier_notif_fd)
{
	struct lttng_event_notifier_group *event_notifier_group;
	int event_notifier_group_objd, ret, fd_flag;

	event_notifier_group = lttng_event_notifier_group_create();
	if (!event_notifier_group)
		return -ENOMEM;

	/*
	 * Set this file descriptor as NON-BLOCKING.
	 */
	fd_flag = fcntl(*event_notifier_notif_fd, F_GETFL);

	fd_flag |= O_NONBLOCK;

	ret = fcntl(*event_notifier_notif_fd, F_SETFL, fd_flag);
	if (ret) {
		ret = -errno;
		goto fd_error;
	}

	event_notifier_group_objd = objd_alloc(event_notifier_group,
		&lttng_event_notifier_group_ops, owner, "event_notifier_group");
	if (event_notifier_group_objd < 0) {
		ret = event_notifier_group_objd;
		goto objd_error;
	}

	event_notifier_group->objd = event_notifier_group_objd;
	event_notifier_group->owner = owner;
	event_notifier_group->notification_fd = *event_notifier_notif_fd;
	/* Object descriptor takes ownership of notification fd. */
	*event_notifier_notif_fd = -1;

	return event_notifier_group_objd;

objd_error:
	lttng_event_notifier_group_destroy(event_notifier_group);
fd_error:
	return ret;
}

static
long lttng_abi_add_context(int objd __attribute__((unused)),
	struct lttng_ust_abi_context *context_param,
	union lttng_ust_abi_args *uargs,
	struct lttng_ust_ctx **ctx, struct lttng_ust_session *session)
{
	return lttng_attach_context(context_param, uargs, ctx, session);
}

/**
 *	lttng_cmd - lttng control through socket commands
 *
 *	@objd: the object descriptor
 *	@cmd: the command
 *	@arg: command arg
 *	@uargs: UST arguments (internal)
 *	@owner: objd owner
 *
 *	This descriptor implements lttng commands:
 *	LTTNG_UST_ABI_SESSION
 *		Returns a LTTng trace session object descriptor
 *	LTTNG_UST_ABI_TRACER_VERSION
 *		Returns the LTTng kernel tracer version
 *	LTTNG_UST_ABI_TRACEPOINT_LIST
 *		Returns a file descriptor listing available tracepoints
 *	LTTNG_UST_ABI_TRACEPOINT_FIELD_LIST
 *		Returns a file descriptor listing available tracepoint fields
 *	LTTNG_UST_ABI_WAIT_QUIESCENT
 *		Returns after all previously running probes have completed
 *
 * The returned session will be deleted when its file descriptor is closed.
 */
static
long lttng_cmd(int objd, unsigned int cmd, unsigned long arg,
	union lttng_ust_abi_args *uargs, void *owner)
{
	switch (cmd) {
	case LTTNG_UST_ABI_SESSION:
		return lttng_abi_create_session(owner);
	case LTTNG_UST_ABI_TRACER_VERSION:
		return lttng_abi_tracer_version(objd,
				(struct lttng_ust_abi_tracer_version *) arg);
	case LTTNG_UST_ABI_TRACEPOINT_LIST:
		return lttng_abi_tracepoint_list(owner);
	case LTTNG_UST_ABI_TRACEPOINT_FIELD_LIST:
		return lttng_abi_tracepoint_field_list(owner);
	case LTTNG_UST_ABI_WAIT_QUIESCENT:
		lttng_ust_urcu_synchronize_rcu();
		return 0;
	case LTTNG_UST_ABI_EVENT_NOTIFIER_GROUP_CREATE:
		return lttng_abi_event_notifier_send_fd(owner,
			&uargs->event_notifier_handle.event_notifier_notif_fd);
	default:
		return -EINVAL;
	}
}

static const struct lttng_ust_abi_objd_ops lttng_ops = {
	.cmd = lttng_cmd,
};

static
int lttng_abi_map_channel(int session_objd,
		struct lttng_ust_abi_channel *ust_chan,
		union lttng_ust_abi_args *uargs,
		void *owner)
{
	struct lttng_ust_session *session = objd_private(session_objd);
	const char *transport_name;
	struct lttng_transport *transport;
	const char *chan_name;
	int chan_objd;
	struct lttng_ust_shm_handle *channel_handle;
	struct lttng_ust_abi_channel_config *lttng_chan_config;
	struct lttng_ust_channel_buffer *lttng_chan_buf;
	struct lttng_ust_ring_buffer_channel *chan;
	struct lttng_ust_ring_buffer_config *config;
	void *chan_data;
	int wakeup_fd;
	uint64_t len;
	int ret;
	enum lttng_ust_abi_chan_type type;

	chan_data = uargs->channel.chan_data;
	wakeup_fd = uargs->channel.wakeup_fd;
	len = ust_chan->len;
	type = ust_chan->type;

	switch (type) {
	case LTTNG_UST_ABI_CHAN_PER_CPU:
		break;
	case LTTNG_UST_ABI_CHAN_PER_CHANNEL:
		break;
	default:
		ret = -EINVAL;
		goto invalid;
	}

	if (session->priv->been_active) {
		ret = -EBUSY;
		goto active;	/* Refuse to add channel to active session */
	}

	lttng_chan_buf = lttng_ust_alloc_channel_buffer();
	if (!lttng_chan_buf) {
		ret = -ENOMEM;
		goto lttng_chan_buf_error;
	}

	channel_handle = channel_handle_create(chan_data, len, wakeup_fd);
	if (!channel_handle) {
		ret = -EINVAL;
		goto handle_error;
	}

	/* Ownership of chan_data and wakeup_fd taken by channel handle. */
	uargs->channel.chan_data = NULL;
	uargs->channel.wakeup_fd = -1;

	chan = shmp(channel_handle, channel_handle->chan);
	assert(chan);
	chan->handle = channel_handle;
	config = &chan->backend.config;
	lttng_chan_config = channel_get_private_config(chan);
	if (!lttng_chan_config) {
		ret = -EINVAL;
		goto alloc_error;
	}

	if (lttng_ust_session_uuid_validate(session, lttng_chan_config->uuid)) {
		ret = -EINVAL;
		goto uuid_error;
	}

	/* Lookup transport name */
	switch (type) {
	case LTTNG_UST_ABI_CHAN_PER_CPU:
		if (config->output == RING_BUFFER_MMAP) {
			if (config->mode == RING_BUFFER_OVERWRITE) {
				if (config->wakeup == RING_BUFFER_WAKEUP_BY_WRITER) {
					transport_name = "relay-overwrite-mmap";
				} else {
					transport_name = "relay-overwrite-rt-mmap";
				}
			} else {
				if (config->wakeup == RING_BUFFER_WAKEUP_BY_WRITER) {
					transport_name = "relay-discard-mmap";
				} else {
					transport_name = "relay-discard-rt-mmap";
				}
			}
		} else {
			ret = -EINVAL;
			goto notransport;
		}
		chan_name = "channel";
		break;
	case LTTNG_UST_ABI_CHAN_PER_CHANNEL:
		if (config->output == RING_BUFFER_MMAP) {
			if (config->mode == RING_BUFFER_OVERWRITE) {
				if (config->wakeup == RING_BUFFER_WAKEUP_BY_WRITER) {
					transport_name = "relay-overwrite-channel-mmap";
				} else {
					transport_name = "relay-overwrite-channel-rt-mmap";
				}
			} else {
				if (config->wakeup == RING_BUFFER_WAKEUP_BY_WRITER) {
					transport_name = "relay-discard-channel-mmap";
				} else {
					transport_name = "relay-discard-channel-rt-mmap";
				}
			}
		} else {
			ret = -EINVAL;
			goto notransport;
		}
		chan_name = "channel";
		break;
	default:
		ret = -EINVAL;
		goto notransport;
	}
	transport = lttng_ust_transport_find(transport_name);
	if (!transport) {
		DBG("LTTng transport %s not found\n",
		       transport_name);
		ret = -EINVAL;
		goto notransport;
	}

	chan_objd = objd_alloc(NULL, &lttng_channel_ops, owner, chan_name);
	if (chan_objd < 0) {
		ret = chan_objd;
		goto objd_error;
	}

	/* Initialize our lttng chan */
	lttng_chan_buf->parent->enabled = 1;
	lttng_chan_buf->parent->session = session;

	lttng_chan_buf->priv->parent.tstate = 1;
	lttng_chan_buf->priv->ctx = NULL;
	lttng_chan_buf->priv->rb_chan = chan;

	lttng_chan_buf->ops = &transport->ops;

	memcpy(&chan->backend.config,
		transport->client_config,
		sizeof(chan->backend.config));
	cds_list_add(&lttng_chan_buf->priv->node, &session->priv->chan_head);
	lttng_chan_buf->priv->header_type = 0;
	lttng_chan_buf->priv->type = type;
	/* Copy fields from lttng ust chan config. */
	lttng_chan_buf->priv->id = lttng_chan_config->id;
	memcpy(lttng_chan_buf->priv->uuid, lttng_chan_config->uuid, LTTNG_UST_UUID_LEN);
	channel_set_private(chan, lttng_chan_buf);

	/*
	 * We tolerate no failure path after channel creation. It will stay
	 * invariant for the rest of the session.
	 */
	objd_set_private(chan_objd, lttng_chan_buf);
	lttng_chan_buf->priv->parent.objd = chan_objd;
	/* The channel created holds a reference on the session */
	objd_ref(session_objd);
	return chan_objd;

	/* error path after channel was created */
objd_error:
notransport:
uuid_error:
alloc_error:
	channel_destroy(chan, channel_handle, 0);
	lttng_ust_free_channel_common(lttng_chan_buf->parent);
	return ret;

handle_error:
	lttng_ust_free_channel_common(lttng_chan_buf->parent);
lttng_chan_buf_error:
active:
invalid:
	return ret;
}

static
bool check_zero(const char *p, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (p[i] != 0)
			return false;
	}
	return true;
}

static
int copy_abi_struct(void *dst_struct, size_t dst_struct_len,
		const void *src_struct, size_t src_struct_len)
{
	if (dst_struct_len >= src_struct_len) {
		memcpy(dst_struct, src_struct, src_struct_len);
		if (dst_struct_len > src_struct_len)
			memset(dst_struct + src_struct_len, 0, dst_struct_len - src_struct_len);
	} else {	/* dst_struct_len < src_struct_len */
		/* Validate zero-padding. */
		if (!check_zero(src_struct + dst_struct_len, src_struct_len - dst_struct_len))
			return -E2BIG;
		memcpy(dst_struct, src_struct, dst_struct_len);
	}
	return 0;
}

static
long lttng_session_create_counter(
		int session_objd,
		const struct lttng_ust_abi_counter_conf *abi_counter_conf,
		union lttng_ust_abi_args *uargs,
		void *owner)
{
	struct lttng_ust_session *session = objd_private(session_objd);
	int counter_objd, ret;
	const char *counter_transport_name;
	struct lttng_ust_channel_counter *counter = NULL;
	struct lttng_counter_dimension dimensions[1] = {};
	size_t number_dimensions = 1;
	struct lttng_ust_abi_counter_conf counter_conf;
	uint32_t min_expected_len = lttng_ust_offsetofend(struct lttng_ust_abi_counter_conf, elem_len);
	const struct lttng_ust_abi_counter_dimension *abi_dimension;
	struct lttng_ust_abi_counter_dimension dimension;

	if (uargs->counter.len < min_expected_len) {
		ERR("LTTng: Map: Counter configuration of wrong size.");
		return -EINVAL;
	}
	if (abi_counter_conf->len > uargs->counter.len || abi_counter_conf->len < lttng_ust_offsetofend(struct lttng_ust_abi_counter_conf, elem_len)) {
		return -EINVAL;
	}
	ret = copy_abi_struct(&counter_conf, sizeof(counter_conf), abi_counter_conf, abi_counter_conf->len);
	if (ret) {
		ERR("Unexpected counter configuration structure content");
		return ret;
	}
	if (counter_conf.number_dimensions != 1) {
		ERR("LTTng: Map: Unsupprted number of dimensions %u.", counter_conf.number_dimensions);
		return -EINVAL;
	}
	if (counter_conf.elem_len < lttng_ust_offsetofend(struct lttng_ust_abi_counter_dimension, overflow_index)) {
		ERR("Unexpected dimension array element length %u.", counter_conf.elem_len);
		return -EINVAL;
	}
	if (counter_conf.len + counter_conf.elem_len > uargs->counter.len) {
		return -EINVAL;
	}
	abi_dimension = (const struct lttng_ust_abi_counter_dimension *)(((char *)abi_counter_conf) + counter_conf.len);
	ret = copy_abi_struct(&dimension, sizeof(dimension), abi_dimension, counter_conf.elem_len);
	if (ret) {
		ERR("Unexpected dimension structure content");
		return ret;
	}
	if (counter_conf.arithmetic != LTTNG_UST_ABI_COUNTER_ARITHMETIC_MODULAR) {
		ERR("LTTng: Map: Counter of the wrong type.");
		return -EINVAL;
	}
	if (counter_conf.global_sum_step) {
		/* Unsupported. */
		return -EINVAL;
	}
	switch (counter_conf.bitness) {
	case LTTNG_UST_ABI_COUNTER_BITNESS_64:
		counter_transport_name = "counter-per-cpu-64-modular";
		break;
	case LTTNG_UST_ABI_COUNTER_BITNESS_32:
		counter_transport_name = "counter-per-cpu-32-modular";
		break;
	default:
		return -EINVAL;
	}

	dimensions[0].size = dimension.size;
	dimensions[0].underflow_index = dimension.underflow_index;
	dimensions[0].overflow_index = dimension.overflow_index;
	dimensions[0].has_underflow = dimension.flags & LTTNG_UST_ABI_COUNTER_DIMENSION_FLAG_UNDERFLOW;
	dimensions[0].has_overflow = dimension.flags & LTTNG_UST_ABI_COUNTER_DIMENSION_FLAG_OVERFLOW;
	switch (dimension.key_type) {
	case LTTNG_UST_ABI_KEY_TYPE_TOKENS:
		dimensions[0].key_type = LTTNG_KEY_TYPE_TOKENS;
		break;
	case LTTNG_UST_ABI_KEY_TYPE_INTEGER:	/* Fall-through */
	default:
		return -EINVAL;
	}

	counter_objd = objd_alloc(NULL, &lttng_counter_ops, owner, "counter");
	if (counter_objd < 0) {
		ret = counter_objd;
		goto objd_error;
	}

	counter = lttng_ust_counter_create(counter_transport_name,
			number_dimensions, dimensions,
			0, counter_conf.flags & LTTNG_UST_ABI_COUNTER_CONF_FLAG_COALESCE_HITS);
	if (!counter) {
		ret = -EINVAL;
		goto counter_error;
	}
	counter->parent->session = session;
	cds_list_add(&counter->priv->node, &session->priv->counters_head);
	objd_set_private(counter_objd, counter);
	counter->priv->parent.objd = counter_objd;
	counter->priv->parent.tstate = 1;
	counter->parent->enabled = 1;
	/* The channel created holds a reference on the session */
	objd_ref(session_objd);
	return counter_objd;

counter_error:
	{
		int err;

		err = lttng_ust_abi_objd_unref(counter_objd, 1);
		assert(!err);
	}
objd_error:
	return ret;
}

/**
 *	lttng_session_cmd - lttng session object command
 *
 *	@obj: the object
 *	@cmd: the command
 *	@arg: command arg
 *	@uargs: UST arguments (internal)
 *	@owner: objd owner
 *
 *	This descriptor implements lttng commands:
 *	LTTNG_UST_ABI_CHANNEL
 *		Returns a LTTng channel object descriptor
 *	LTTNG_UST_ABI_ENABLE
 *		Enables tracing for a session (weak enable)
 *	LTTNG_UST_ABI_DISABLE
 *		Disables tracing for a session (strong disable)
 *
 * The returned channel will be deleted when its file descriptor is closed.
 */
static
long lttng_session_cmd(int objd, unsigned int cmd, unsigned long arg,
	union lttng_ust_abi_args *uargs, void *owner)
{
	struct lttng_ust_session *session = objd_private(objd);

	switch (cmd) {
	case LTTNG_UST_ABI_CHANNEL:
		return lttng_abi_map_channel(objd,
				(struct lttng_ust_abi_channel *) arg,
				uargs, owner);
	case LTTNG_UST_ABI_SESSION_START:
	case LTTNG_UST_ABI_ENABLE:
		return lttng_session_enable(session);
	case LTTNG_UST_ABI_SESSION_STOP:
	case LTTNG_UST_ABI_DISABLE:
		return lttng_session_disable(session);
	case LTTNG_UST_ABI_SESSION_STATEDUMP:
		return lttng_session_statedump(session);
	case LTTNG_UST_ABI_COUNTER:
		return lttng_session_create_counter(objd,
				(struct lttng_ust_abi_counter_conf *)arg,
				uargs, owner);
	default:
		return -EINVAL;
	}
}

/*
 * Called when the last file reference is dropped.
 *
 * Big fat note: channels and events are invariant for the whole session after
 * their creation. So this session destruction also destroys all channel and
 * event structures specific to this session (they are not destroyed when their
 * individual file is released).
 */
static
int lttng_release_session(int objd)
{
	struct lttng_ust_session *session = objd_private(objd);

	if (session) {
		lttng_session_destroy(session);
		return 0;
	} else {
		return -EINVAL;
	}
}

static const struct lttng_ust_abi_objd_ops lttng_session_ops = {
	.release = lttng_release_session,
	.cmd = lttng_session_cmd,
};

static int lttng_ust_event_notifier_enabler_create(int event_notifier_group_obj,
		void *owner, struct lttng_ust_abi_event_notifier *event_notifier_param,
		enum lttng_enabler_format_type type)
{
	struct lttng_event_notifier_group *event_notifier_group =
		objd_private(event_notifier_group_obj);
	struct lttng_event_notifier_enabler *event_notifier_enabler;
	int event_notifier_objd, ret;

	event_notifier_param->event.name[LTTNG_UST_ABI_SYM_NAME_LEN - 1] = '\0';
	event_notifier_objd = objd_alloc(NULL, &lttng_event_notifier_enabler_ops, owner,
		"event_notifier enabler");
	if (event_notifier_objd < 0) {
		ret = event_notifier_objd;
		goto objd_error;
	}

	event_notifier_enabler = lttng_event_notifier_enabler_create(
		event_notifier_group, type, event_notifier_param);
	if (!event_notifier_enabler) {
		ret = -ENOMEM;
		goto event_notifier_error;
	}

	objd_set_private(event_notifier_objd, event_notifier_enabler);
	/* The event_notifier holds a reference on the event_notifier group. */
	objd_ref(event_notifier_enabler->group->objd);

	return event_notifier_objd;

event_notifier_error:
	{
		int err;

		err = lttng_ust_abi_objd_unref(event_notifier_objd, 1);
		assert(!err);
	}
objd_error:
	return ret;
}

static
long lttng_event_notifier_enabler_cmd(int objd, unsigned int cmd, unsigned long arg,
		union lttng_ust_abi_args *uargs __attribute__((unused)),
		void *owner __attribute__((unused)))
{
	struct lttng_event_notifier_enabler *event_notifier_enabler = objd_private(objd);
	switch (cmd) {
	case LTTNG_UST_ABI_FILTER:
		return lttng_event_enabler_attach_filter_bytecode(
			&event_notifier_enabler->parent,
			(struct lttng_ust_bytecode_node **) arg);
	case LTTNG_UST_ABI_EXCLUSION:
		return lttng_event_enabler_attach_exclusion(&event_notifier_enabler->parent,
			(struct lttng_ust_excluder_node **) arg);
	case LTTNG_UST_ABI_CAPTURE:
		return lttng_event_notifier_enabler_attach_capture_bytecode(
			event_notifier_enabler,
			(struct lttng_ust_bytecode_node **) arg);
	case LTTNG_UST_ABI_ENABLE:
		return lttng_event_enabler_enable(&event_notifier_enabler->parent);
	case LTTNG_UST_ABI_DISABLE:
		return lttng_event_enabler_disable(&event_notifier_enabler->parent);
	default:
		return -EINVAL;
	}
}

/**
 *	lttng_event_notifier_group_error_counter_cmd - lttng event_notifier group error counter object command
 *
 *	@obj: the object
 *	@cmd: the command
 *	@arg: command arg
 *	@uargs: UST arguments (internal)
 *	@owner: objd owner
 *
 *	This descriptor implements lttng commands:
 *      LTTNG_UST_ABI_COUNTER_CHANNEL
 *        Return negative error code on error, 0 on success.
 *      LTTNG_UST_ABI_COUNTER_CPU
 *        Return negative error code on error, 0 on success.
 */
static
long lttng_event_notifier_group_error_counter_cmd(int objd, unsigned int cmd, unsigned long arg,
	union lttng_ust_abi_args *uargs, void *owner __attribute__((unused)))
{
	int ret;
	struct lttng_ust_channel_counter *counter = objd_private(objd);

	switch (cmd) {
	case LTTNG_UST_ABI_COUNTER_CHANNEL:
		ret = -EINVAL;	/* Unimplemented. */
		break;
	case LTTNG_UST_ABI_COUNTER_CPU:
	{
		struct lttng_ust_abi_counter_cpu *abi_counter_cpu =
			(struct lttng_ust_abi_counter_cpu *) arg;
		struct lttng_ust_abi_counter_cpu counter_cpu;

		if (abi_counter_cpu->len < lttng_ust_offsetofend(struct lttng_ust_abi_counter_cpu, cpu_nr)) {
			return -EINVAL;
		}
		ret = copy_abi_struct(&counter_cpu, sizeof(counter_cpu),
				abi_counter_cpu, abi_counter_cpu->len);
		if (ret)
			return ret;
		ret = lttng_counter_set_cpu_shm(counter->priv->counter,
			counter_cpu.cpu_nr, uargs->counter_shm.shm_fd);
		if (!ret) {
			/* Take ownership of the shm_fd. */
			uargs->counter_shm.shm_fd = -1;
		}
		break;
	}
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

int lttng_release_event_notifier_group_error_counter(int objd)
	__attribute__((visibility("hidden")));
int lttng_release_event_notifier_group_error_counter(int objd)
{
	struct lttng_ust_channel_counter *counter = objd_private(objd);

	if (counter) {
		return lttng_ust_abi_objd_unref(counter->priv->event_notifier_group->objd, 0);
	} else {
		return -EINVAL;
	}
}

static const struct lttng_ust_abi_objd_ops lttng_event_notifier_group_error_counter_ops = {
	.release = lttng_release_event_notifier_group_error_counter,
	.cmd = lttng_event_notifier_group_error_counter_cmd,
};

static
int lttng_ust_event_notifier_group_create_error_counter(int event_notifier_group_objd,
		struct lttng_ust_abi_counter_conf *abi_counter_conf,
		union lttng_ust_abi_args *uargs,
		void *owner)
{
	const char *counter_transport_name;
	struct lttng_event_notifier_group *event_notifier_group =
		objd_private(event_notifier_group_objd);
	struct lttng_ust_channel_counter *counter;
	int counter_objd, ret;
	size_t counter_len;
	struct lttng_counter_dimension dimensions[1] = {};
	struct lttng_ust_abi_counter_conf counter_conf;
	uint32_t min_expected_len = lttng_ust_offsetofend(struct lttng_ust_abi_counter_conf, elem_len);
	const struct lttng_ust_abi_counter_dimension *abi_dimension;
	struct lttng_ust_abi_counter_dimension dimension;

	if (event_notifier_group->error_counter)
		return -EBUSY;

	if (uargs->counter.len < min_expected_len) {
		ERR("LTTng: Counter configuration of wrong size.");
		return -EINVAL;
	}
	if (abi_counter_conf->len > uargs->counter.len || abi_counter_conf->len < lttng_ust_offsetofend(struct lttng_ust_abi_counter_conf, elem_len)) {
		return -EINVAL;
	}
	ret = copy_abi_struct(&counter_conf, sizeof(counter_conf), abi_counter_conf, abi_counter_conf->len);
	if (ret) {
		ERR("Unexpected counter configuration structure content");
		return ret;
	}
	if (counter_conf.number_dimensions != 1) {
		ERR("LTTng: Map: Unsupprted number of dimensions %u.", counter_conf.number_dimensions);
		return -EINVAL;
	}
	if (counter_conf.elem_len < lttng_ust_offsetofend(struct lttng_ust_abi_counter_dimension, overflow_index)) {
		ERR("Unexpected dimension array element length %u.", counter_conf.elem_len);
		return -EINVAL;
	}
	if (counter_conf.len + counter_conf.elem_len > uargs->counter.len) {
		return -EINVAL;
	}
	abi_dimension = (const struct lttng_ust_abi_counter_dimension *)(((char *)abi_counter_conf) + counter_conf.len);
	ret = copy_abi_struct(&dimension, sizeof(dimension), abi_dimension, counter_conf.elem_len);
	if (ret) {
		ERR("Unexpected dimension structure content");
		return ret;
	}
	if (counter_conf.arithmetic != LTTNG_UST_ABI_COUNTER_ARITHMETIC_MODULAR) {
		ERR("LTTng: Counter of the wrong type.");
		return -EINVAL;
	}
	if (counter_conf.global_sum_step) {
		/* Unsupported. */
		return -EINVAL;
	}
	switch (counter_conf.bitness) {
	case LTTNG_UST_ABI_COUNTER_BITNESS_64:
		counter_transport_name = "counter-per-cpu-64-modular";
		break;
	case LTTNG_UST_ABI_COUNTER_BITNESS_32:
		counter_transport_name = "counter-per-cpu-32-modular";
		break;
	default:
		return -EINVAL;
	}

	counter_len = dimension.size;
	dimensions[0].size = counter_len;
	dimensions[0].underflow_index = dimension.underflow_index;
	dimensions[0].overflow_index = dimension.overflow_index;
	dimensions[0].has_underflow = dimension.flags & LTTNG_UST_ABI_COUNTER_DIMENSION_FLAG_UNDERFLOW;
	dimensions[0].has_overflow = dimension.flags & LTTNG_UST_ABI_COUNTER_DIMENSION_FLAG_OVERFLOW;

	counter_objd = objd_alloc(NULL, &lttng_event_notifier_group_error_counter_ops, owner,
		"event_notifier group error counter");
	if (counter_objd < 0) {
		ret = counter_objd;
		goto objd_error;
	}

	counter = lttng_ust_counter_create(counter_transport_name, 1, dimensions, 0, false);
	if (!counter) {
		ret = -EINVAL;
		goto create_error;
	}

	event_notifier_group->error_counter_len = counter_len;
	/*
	 * store-release to publish error counter matches load-acquire
	 * in record_error. Ensures the counter is created and the
	 * error_counter_len is set before they are used.
	 * Currently a full memory barrier is used, which could be
	 * turned into acquire-release barriers.
	 */
	cmm_smp_mb();
	CMM_STORE_SHARED(event_notifier_group->error_counter, counter);

	counter->priv->parent.objd = counter_objd;
	counter->priv->event_notifier_group = event_notifier_group;	/* owner */

	objd_set_private(counter_objd, counter);
	/* The error counter holds a reference on the event_notifier group. */
	objd_ref(event_notifier_group->objd);

	return counter_objd;

create_error:
	{
		int err;

		err = lttng_ust_abi_objd_unref(counter_objd, 1);
		assert(!err);
	}
objd_error:
	return ret;
}

static
long lttng_event_notifier_group_cmd(int objd, unsigned int cmd, unsigned long arg,
		union lttng_ust_abi_args *uargs, void *owner)
{
	int ret;

	switch (cmd) {
	case LTTNG_UST_ABI_EVENT_NOTIFIER_CREATE:
	{
		struct lttng_ust_abi_event_notifier *abi_event_notifier =
			(struct lttng_ust_abi_event_notifier *) arg;
		struct lttng_ust_abi_event_notifier event_notifier = {};

		if (uargs->event_notifier.len < lttng_ust_offsetofend(struct lttng_ust_abi_event_notifier, error_counter_index))
			return -EINVAL;
		ret = copy_abi_struct(&event_notifier, sizeof(event_notifier),
				abi_event_notifier, uargs->event_notifier.len);
		if (ret)
			return ret;
		event_notifier.event.name[LTTNG_UST_ABI_SYM_NAME_LEN - 1] = '\0';
		if (strutils_is_star_glob_pattern(event_notifier.event.name)) {
			/*
			 * If the event name is a star globbing pattern,
			 * we create the special star globbing enabler.
			 */
			return lttng_ust_event_notifier_enabler_create(objd,
					owner, &event_notifier,
					LTTNG_ENABLER_FORMAT_STAR_GLOB);
		} else {
			return lttng_ust_event_notifier_enabler_create(objd,
					owner, &event_notifier,
					LTTNG_ENABLER_FORMAT_EVENT);
		}
	}
	case LTTNG_UST_ABI_COUNTER:
	{
		return lttng_ust_event_notifier_group_create_error_counter(
				objd, (struct lttng_ust_abi_counter_conf *) arg, uargs, owner);
	}
	default:
		return -EINVAL;
	}
}

static
int lttng_event_notifier_enabler_release(int objd)
{
	struct lttng_event_notifier_enabler *event_notifier_enabler = objd_private(objd);

	if (event_notifier_enabler)
		return lttng_ust_abi_objd_unref(event_notifier_enabler->group->objd, 0);
	return 0;
}

static const struct lttng_ust_abi_objd_ops lttng_event_notifier_enabler_ops = {
	.release = lttng_event_notifier_enabler_release,
	.cmd = lttng_event_notifier_enabler_cmd,
};

static
int lttng_release_event_notifier_group(int objd)
{
	struct lttng_event_notifier_group *event_notifier_group = objd_private(objd);

	if (event_notifier_group) {
		lttng_event_notifier_group_destroy(event_notifier_group);
		return 0;
	} else {
		return -EINVAL;
	}
}

static const struct lttng_ust_abi_objd_ops lttng_event_notifier_group_ops = {
	.release = lttng_release_event_notifier_group,
	.cmd = lttng_event_notifier_group_cmd,
};

static
long lttng_tracepoint_list_cmd(int objd, unsigned int cmd, unsigned long arg,
	union lttng_ust_abi_args *uargs __attribute__((unused)),
	void *owner __attribute__((unused)))
{
	struct lttng_ust_tracepoint_list *list = objd_private(objd);
	struct lttng_ust_abi_tracepoint_iter *tp =
		(struct lttng_ust_abi_tracepoint_iter *) arg;
	struct lttng_ust_abi_tracepoint_iter *iter;

	switch (cmd) {
	case LTTNG_UST_ABI_TRACEPOINT_LIST_GET:
	{
		iter = lttng_ust_tracepoint_list_get_iter_next(list);
		if (!iter)
			return -LTTNG_UST_ERR_NOENT;
		memcpy(tp, iter, sizeof(*tp));
		return 0;
	}
	default:
		return -EINVAL;
	}
}

static
int lttng_abi_tracepoint_list(void *owner)
{
	int list_objd, ret;
	struct lttng_ust_tracepoint_list *list;

	list_objd = objd_alloc(NULL, &lttng_tracepoint_list_ops, owner, "tp_list");
	if (list_objd < 0) {
		ret = list_objd;
		goto objd_error;
	}
	list = zmalloc(sizeof(*list));
	if (!list) {
		ret = -ENOMEM;
		goto alloc_error;
	}
	objd_set_private(list_objd, list);

	/* populate list by walking on all registered probes. */
	ret = lttng_probes_get_event_list(list);
	if (ret) {
		goto list_error;
	}
	return list_objd;

list_error:
	free(list);
alloc_error:
	{
		int err;

		err = lttng_ust_abi_objd_unref(list_objd, 1);
		assert(!err);
	}
objd_error:
	return ret;
}

static
int lttng_release_tracepoint_list(int objd)
{
	struct lttng_ust_tracepoint_list *list = objd_private(objd);

	if (list) {
		lttng_probes_prune_event_list(list);
		free(list);
		return 0;
	} else {
		return -EINVAL;
	}
}

static const struct lttng_ust_abi_objd_ops lttng_tracepoint_list_ops = {
	.release = lttng_release_tracepoint_list,
	.cmd = lttng_tracepoint_list_cmd,
};

static
long lttng_tracepoint_field_list_cmd(int objd, unsigned int cmd,
	unsigned long arg __attribute__((unused)), union lttng_ust_abi_args *uargs,
	void *owner __attribute__((unused)))
{
	struct lttng_ust_field_list *list = objd_private(objd);
	struct lttng_ust_abi_field_iter *tp = &uargs->field_list.entry;
	struct lttng_ust_abi_field_iter *iter;

	switch (cmd) {
	case LTTNG_UST_ABI_TRACEPOINT_FIELD_LIST_GET:
	{
		iter = lttng_ust_field_list_get_iter_next(list);
		if (!iter)
			return -LTTNG_UST_ERR_NOENT;
		memcpy(tp, iter, sizeof(*tp));
		return 0;
	}
	default:
		return -EINVAL;
	}
}

static
int lttng_abi_tracepoint_field_list(void *owner)
{
	int list_objd, ret;
	struct lttng_ust_field_list *list;

	list_objd = objd_alloc(NULL, &lttng_tracepoint_field_list_ops, owner,
			"tp_field_list");
	if (list_objd < 0) {
		ret = list_objd;
		goto objd_error;
	}
	list = zmalloc(sizeof(*list));
	if (!list) {
		ret = -ENOMEM;
		goto alloc_error;
	}
	objd_set_private(list_objd, list);

	/* populate list by walking on all registered probes. */
	ret = lttng_probes_get_field_list(list);
	if (ret) {
		goto list_error;
	}
	return list_objd;

list_error:
	free(list);
alloc_error:
	{
		int err;

		err = lttng_ust_abi_objd_unref(list_objd, 1);
		assert(!err);
	}
objd_error:
	return ret;
}

static
int lttng_release_tracepoint_field_list(int objd)
{
	struct lttng_ust_field_list *list = objd_private(objd);

	if (list) {
		lttng_probes_prune_field_list(list);
		free(list);
		return 0;
	} else {
		return -EINVAL;
	}
}

static const struct lttng_ust_abi_objd_ops lttng_tracepoint_field_list_ops = {
	.release = lttng_release_tracepoint_field_list,
	.cmd = lttng_tracepoint_field_list_cmd,
};

static
int lttng_abi_map_stream(int channel_objd, struct lttng_ust_abi_stream *info,
		union lttng_ust_abi_args *uargs, void *owner __attribute__((unused)))
{
	struct lttng_ust_channel_buffer *lttng_chan_buf = objd_private(channel_objd);
	int ret;

	ret = channel_handle_add_stream(lttng_chan_buf->priv->rb_chan->handle,
		uargs->stream.shm_fd, uargs->stream.wakeup_fd,
		info->stream_nr, info->len);
	if (ret)
		goto error_add_stream;
	/* Take ownership of shm_fd and wakeup_fd. */
	uargs->stream.shm_fd = -1;
	uargs->stream.wakeup_fd = -1;

	return 0;

error_add_stream:
	return ret;
}

static
int lttng_abi_create_event_recorder_enabler(int channel_objd,
			struct lttng_ust_channel_buffer *channel,
			struct lttng_ust_abi_event *event_param,
			void *owner,
			enum lttng_enabler_format_type format_type)
{
	struct lttng_event_recorder_enabler *enabler;
	int event_objd, ret;

	event_param->name[LTTNG_UST_ABI_SYM_NAME_LEN - 1] = '\0';
	event_objd = objd_alloc(NULL, &lttng_event_enabler_ops, owner,
		"event recorder enabler");
	if (event_objd < 0) {
		ret = event_objd;
		goto objd_error;
	}
	/*
	 * We tolerate no failure path after event creation. It will stay
	 * invariant for the rest of the session.
	 */
	enabler = lttng_event_recorder_enabler_create(format_type, event_param,
			channel);
	if (!enabler) {
		ret = -ENOMEM;
		goto event_error;
	}
	objd_set_private(event_objd, &enabler->parent);
	/* The event holds a reference on the channel */
	objd_ref(channel_objd);
	return event_objd;

event_error:
	{
		int err;

		err = lttng_ust_abi_objd_unref(event_objd, 1);
		assert(!err);
	}
objd_error:
	return ret;
}

#ifdef CONFIG_LTTNG_UST_EXPERIMENTAL_COUNTER
static
int copy_counter_key_dimension_tokens(const struct lttng_ust_abi_counter_key_dimension_tokens *abi_dim_tokens,
		const char *addr, size_t *offset, size_t arg_len, struct lttng_counter_key_dimension *internal_dim)
{
	struct lttng_ust_abi_counter_key_dimension_tokens dim_tokens;
	size_t nr_key_tokens, j;
	int ret;

	if (abi_dim_tokens->parent.len < sizeof(struct lttng_ust_abi_counter_key_dimension_tokens))
		return -EINVAL;
	ret = copy_abi_struct(&dim_tokens, sizeof(dim_tokens), abi_dim_tokens, abi_dim_tokens->parent.len);
	if (ret)
		return ret;
	nr_key_tokens = dim_tokens.nr_key_tokens;
	if (!nr_key_tokens || nr_key_tokens > LTTNG_NR_KEY_TOKEN)
		return -EINVAL;
	internal_dim->key_type = LTTNG_KEY_TYPE_TOKENS;
	internal_dim->u.tokens.nr_key_tokens = nr_key_tokens;
	*offset += sizeof(struct lttng_ust_abi_counter_key_dimension_tokens);
	for (j = 0; j < nr_key_tokens; j++) {
		struct lttng_key_token *internal_token = &internal_dim->u.tokens.key_tokens[j];
		const struct lttng_ust_abi_key_token *abi_token;

		if (*offset + sizeof(struct lttng_ust_abi_key_token) > arg_len)
			return -EINVAL;
		abi_token = (const struct lttng_ust_abi_key_token *)(addr + *offset);
		if (abi_token->len < sizeof(struct lttng_ust_abi_key_token))
			return -EINVAL;
		if (*offset + abi_token->len > arg_len)
			return -EINVAL;
		switch (abi_token->type) {
		case LTTNG_UST_ABI_KEY_TOKEN_STRING:
		{
			const struct lttng_ust_abi_key_token_string *abi_key_string;
			struct lttng_ust_abi_key_token_string token_string;

			if (abi_token->len < sizeof(struct lttng_ust_abi_key_token_string))
				return -EINVAL;
			abi_key_string = (const struct lttng_ust_abi_key_token_string *)(addr + *offset);
			ret = copy_abi_struct(&token_string, sizeof(token_string), abi_key_string, abi_key_string->parent.len);
			if (ret)
				return ret;
			*offset += abi_key_string->parent.len;
			internal_token->type = LTTNG_KEY_TOKEN_STRING;
			if (!abi_key_string->string_len || abi_key_string->string_len > LTTNG_KEY_TOKEN_STRING_LEN_MAX)
				return -EINVAL;
			*offset += abi_key_string->string_len;
			if (*offset > arg_len)
				return -EINVAL;
			if (abi_key_string->str[abi_key_string->string_len - 1] != '\0' ||
					strlen(abi_key_string->str) + 1 != abi_key_string->string_len)
				return -EINVAL;
			memcpy(internal_token->arg.string, abi_key_string->str, abi_key_string->string_len);
			break;
		}
		case LTTNG_UST_ABI_KEY_TOKEN_EVENT_NAME:
			internal_token->type = LTTNG_KEY_TOKEN_EVENT_NAME;
			*offset += abi_token->len;
			break;
		case LTTNG_UST_ABI_KEY_TOKEN_PROVIDER_NAME:
			internal_token->type = LTTNG_KEY_TOKEN_PROVIDER_NAME;
			*offset += abi_token->len;
			break;
		default:
			return -EINVAL;
		}
	}
	return 0;
}

static
int copy_counter_key(struct lttng_counter_key *internal_key,
		     unsigned long arg, size_t action_fields_len, size_t arg_len,
		     const struct lttng_ust_abi_counter_event *counter_event)
{
	size_t i, nr_dimensions, offset = 0;
	const char *addr = (const char *)arg;
	int ret;

	nr_dimensions = counter_event->number_key_dimensions;
	if (nr_dimensions != 1)
		return -EINVAL;
	internal_key->nr_dimensions = nr_dimensions;
	offset += counter_event->len + action_fields_len;
	for (i = 0; i < nr_dimensions; i++) {
		struct lttng_counter_key_dimension *internal_dim = &internal_key->key_dimensions[i];
		const struct lttng_ust_abi_counter_key_dimension *abi_dim;

		abi_dim = (const struct lttng_ust_abi_counter_key_dimension *)(addr + offset);
		if (offset + abi_dim->len > arg_len || abi_dim->len < lttng_ust_offsetofend(struct lttng_ust_abi_counter_key_dimension, key_type))
			return -EINVAL;
		switch (abi_dim->key_type) {
		case LTTNG_UST_ABI_KEY_TYPE_TOKENS:
		{
			struct lttng_ust_abi_counter_key_dimension_tokens *dim_tokens =
				caa_container_of(abi_dim, struct lttng_ust_abi_counter_key_dimension_tokens, parent);
			ret = copy_counter_key_dimension_tokens(dim_tokens, addr, &offset, arg_len,
					internal_dim);
			if (ret)
				return ret;
			break;
		}
		default:
			return -EINVAL;
		}
	}
	return 0;
}

static
int lttng_abi_create_event_counter_enabler(int channel_objd,
			struct lttng_ust_channel_counter *channel,
			unsigned long arg, size_t arg_len, void *owner)
{
	struct lttng_ust_abi_counter_event *abi_counter_event = (struct lttng_ust_abi_counter_event *)arg;
	struct lttng_ust_abi_counter_event counter_event = {};
	struct lttng_counter_key counter_key = {};
	struct lttng_event_counter_enabler *enabler;
	enum lttng_enabler_format_type format_type;
	size_t action_fields_len = 0;
	int event_objd, ret;
	size_t i;

	if (arg_len < lttng_ust_offsetofend(struct lttng_ust_abi_counter_event, number_key_dimensions)) {
		return -EINVAL;
	}
	if (arg_len < abi_counter_event->len ||
			abi_counter_event->len < lttng_ust_offsetofend(struct lttng_ust_abi_counter_event, number_key_dimensions)) {
		return -EINVAL;
	}
	ret = copy_abi_struct(&counter_event, sizeof(counter_event),
			abi_counter_event, abi_counter_event->len);
	if (ret) {
		return ret;
	}
	switch (counter_event.action) {
	case LTTNG_UST_ABI_COUNTER_ACTION_INCREMENT:
		/* No additional fields specific to this action. */
		break;
	default:
		return -EINVAL;
	}
	counter_event.event.name[LTTNG_UST_ABI_SYM_NAME_LEN - 1] = '\0';
	if (strutils_is_star_glob_pattern(counter_event.event.name)) {
		format_type = LTTNG_ENABLER_FORMAT_STAR_GLOB;
	} else {
		format_type = LTTNG_ENABLER_FORMAT_EVENT;
	}
	ret = copy_counter_key(&counter_key, arg, action_fields_len, arg_len, &counter_event);
	if (ret) {
		return ret;
	}
	/*
	 * Validate that each dimension counter key type match the map
	 * key type.
	 */
	for (i = 0; i < counter_key.nr_dimensions; i++) {
		if (channel->priv->dimension_key_types[i] != counter_key.key_dimensions[i].key_type)
			return -EINVAL;
	}
	event_objd = objd_alloc(NULL, &lttng_event_enabler_ops, owner,
		"event enabler");
	if (event_objd < 0) {
		ret = event_objd;
		goto objd_error;
	}
	/*
	 * We tolerate no failure path after event creation. It will stay
	 * invariant for the rest of the session.
	 */
	enabler = lttng_event_counter_enabler_create(format_type, &counter_event, &counter_key, channel);
	if (!enabler) {
		ret = -ENOMEM;
		goto event_error;
	}
	objd_set_private(event_objd, &enabler->parent);
	/* The event holds a reference on the channel */
	objd_ref(channel_objd);
	return event_objd;

event_error:
	{
		int err;

		err = lttng_ust_abi_objd_unref(event_objd, 1);
		assert(!err);
	}
objd_error:
	return ret;
}
#endif	/* CONFIG_LTTNG_UST_EXPERIMENTAL_COUNTER */

/**
 *	lttng_channel_cmd - lttng control through object descriptors
 *
 *	@objd: the object descriptor
 *	@cmd: the command
 *	@arg: command arg
 *	@uargs: UST arguments (internal)
 *	@owner: objd owner
 *
 *	This object descriptor implements lttng commands:
 *      LTTNG_UST_ABI_STREAM
 *              Returns an event stream object descriptor or failure.
 *              (typically, one event stream records events from one CPU)
 *	LTTNG_UST_ABI_EVENT
 *		Returns an event object descriptor or failure.
 *	LTTNG_UST_ABI_CONTEXT
 *		Prepend a context field to each event in the channel
 *	LTTNG_UST_ABI_ENABLE
 *		Enable recording for events in this channel (weak enable)
 *	LTTNG_UST_ABI_DISABLE
 *		Disable recording for events in this channel (strong disable)
 *
 * Channel and event file descriptors also hold a reference on the session.
 */
static
long lttng_channel_cmd(int objd, unsigned int cmd, unsigned long arg,
	union lttng_ust_abi_args *uargs, void *owner)
{
	struct lttng_ust_channel_buffer *lttng_chan_buf = objd_private(objd);

	if (cmd != LTTNG_UST_ABI_STREAM) {
		/*
		 * Check if channel received all streams.
		 */
		if (!lttng_is_channel_ready(lttng_chan_buf))
			return -EPERM;
	}

	switch (cmd) {
	case LTTNG_UST_ABI_STREAM:
	{
		struct lttng_ust_abi_stream *stream;

		stream = (struct lttng_ust_abi_stream *) arg;
		/* stream used as output */
		return lttng_abi_map_stream(objd, stream, uargs, owner);
	}
	case LTTNG_UST_ABI_EVENT:
	{
		struct lttng_ust_abi_event *event_param =
			(struct lttng_ust_abi_event *) arg;

		if (strutils_is_star_glob_pattern(event_param->name)) {
			/*
			 * If the event name is a star globbing pattern,
			 * we create the special star globbing enabler.
			 */
			return lttng_abi_create_event_recorder_enabler(objd, lttng_chan_buf,
					event_param, owner,
					LTTNG_ENABLER_FORMAT_STAR_GLOB);
		} else {
			return lttng_abi_create_event_recorder_enabler(objd, lttng_chan_buf,
					event_param, owner,
					LTTNG_ENABLER_FORMAT_EVENT);
		}
	}
	case LTTNG_UST_ABI_CONTEXT:
		return lttng_abi_add_context(objd,
				(struct lttng_ust_abi_context *) arg, uargs,
				&lttng_chan_buf->priv->ctx,
				lttng_chan_buf->parent->session);
	case LTTNG_UST_ABI_ENABLE:
		return lttng_channel_enable(lttng_chan_buf->parent);
	case LTTNG_UST_ABI_DISABLE:
		return lttng_channel_disable(lttng_chan_buf->parent);
	case LTTNG_UST_ABI_FLUSH_BUFFER:
		return lttng_chan_buf->ops->priv->flush_buffer(lttng_chan_buf);
	default:
		return -EINVAL;
	}
}

static
int lttng_channel_release(int objd)
{
	struct lttng_ust_channel_buffer *lttng_chan_buf = objd_private(objd);

	if (lttng_chan_buf)
		return lttng_ust_abi_objd_unref(lttng_chan_buf->parent->session->priv->objd, 0);
	return 0;
}

static const struct lttng_ust_abi_objd_ops lttng_channel_ops = {
	.release = lttng_channel_release,
	.cmd = lttng_channel_cmd,
};

/**
 *	lttng_counter_cmd - lttng control through object descriptors
 *
 *	@objd: the object descriptor
 *	@cmd: the command
 *	@arg: command arg
 *	@uargs: UST arguments (internal)
 *	@owner: objd owner
 *
 *	This object descriptor implements lttng commands:
 *      LTTNG_UST_ABI_COUNTER_CHANNEL:
 *              Returns a channel counter object descriptor or failure.
 *      LTTNG_UST_ABI_COUNTER_CPU:
 *              Returns a per-cpu counter object descriptor or failure.
 *	LTTNG_UST_ABI_COUNTER_EVENT
 *		Returns an event object descriptor or failure.
 *	LTTNG_UST_ABI_ENABLE
 *		Enable recording for events in this channel (weak enable)
 *	LTTNG_UST_ABI_DISABLE
 *		Disable recording for events in this channel (strong disable)
 *
 * Counter and event object descriptors also hold a reference on the session.
 */
static
long lttng_counter_cmd(int objd, unsigned int cmd, unsigned long arg,
	union lttng_ust_abi_args *uargs, void *owner __attribute__((unused)))
{
	struct lttng_ust_channel_counter *counter = objd_private(objd);

	if (cmd != LTTNG_UST_ABI_COUNTER_CHANNEL && cmd != LTTNG_UST_ABI_COUNTER_CPU) {
		/*
		 * Check if counter received all per-channel/per-cpu objects.
		 */
		if (!lttng_counter_ready(counter->priv->counter))
			return -EPERM;
	}

	switch (cmd) {
	case LTTNG_UST_ABI_COUNTER_CHANNEL:
	{
		struct lttng_ust_abi_counter_channel *abi_counter_channel =
			(struct lttng_ust_abi_counter_channel *) arg;
		struct lttng_ust_abi_counter_channel counter_channel;
		long ret;
		int shm_fd;

		if (uargs->counter_shm.len < lttng_ust_offsetofend(struct lttng_ust_abi_counter_channel, shm_len))
			return -EINVAL;
		if (abi_counter_channel->len > uargs->counter_shm.len ||
				abi_counter_channel->len < lttng_ust_offsetofend(struct lttng_ust_abi_counter_channel, shm_len)) {
			return -EINVAL;
		}
		ret = copy_abi_struct(&counter_channel, sizeof(counter_channel),
				abi_counter_channel, abi_counter_channel->len);
		if (ret)
			return ret;
		shm_fd = uargs->counter_shm.shm_fd;
		ret = lttng_counter_set_channel_shm(counter->priv->counter, shm_fd);
		if (!ret) {
			/* Take ownership of shm_fd. */
			uargs->counter_shm.shm_fd = -1;
		}
		return ret;
	}
	case LTTNG_UST_ABI_COUNTER_CPU:
	{
		struct lttng_ust_abi_counter_cpu *abi_counter_cpu =
			(struct lttng_ust_abi_counter_cpu *) arg;
		struct lttng_ust_abi_counter_cpu counter_cpu;
		long ret;
		int shm_fd;

		if (uargs->counter_shm.len < lttng_ust_offsetofend(struct lttng_ust_abi_counter_cpu, cpu_nr))
			return -EINVAL;
		if (abi_counter_cpu->len > uargs->counter_shm.len ||
				abi_counter_cpu->len < lttng_ust_offsetofend(struct lttng_ust_abi_counter_cpu, cpu_nr)) {
			return -EINVAL;
		}
		ret = copy_abi_struct(&counter_cpu, sizeof(counter_cpu),
				abi_counter_cpu, abi_counter_cpu->len);
		if (ret)
			return ret;
		shm_fd = uargs->counter_shm.shm_fd;
		ret = lttng_counter_set_cpu_shm(counter->priv->counter,
				counter_cpu.cpu_nr, shm_fd);
		if (!ret) {
			/* Take ownership of shm_fd. */
			uargs->counter_shm.shm_fd = -1;
		}
		return ret;
	}
#ifdef CONFIG_LTTNG_UST_EXPERIMENTAL_COUNTER
	case LTTNG_UST_ABI_COUNTER_EVENT:
	{
		return lttng_abi_create_event_counter_enabler(objd, counter,
				arg, uargs->counter_event.len, owner);
	}
#endif /* CONFIG_LTTNG_UST_EXPERIMENTAL_COUNTER */
	case LTTNG_UST_ABI_ENABLE:
		return lttng_channel_enable(counter->parent);
	case LTTNG_UST_ABI_DISABLE:
		return lttng_channel_disable(counter->parent);
	default:
		return -EINVAL;
	}
}

static
int lttng_counter_release(int objd)
{
	struct lttng_ust_channel_counter *counter = objd_private(objd);

	if (counter) {
		return lttng_ust_abi_objd_unref(counter->parent->session->priv->objd, 0);
	}
	return 0;
}

static const struct lttng_ust_abi_objd_ops lttng_counter_ops = {
	.release = lttng_counter_release,
	.cmd = lttng_counter_cmd,
};

/**
 *	lttng_enabler_cmd - lttng control through object descriptors
 *
 *	@objd: the object descriptor
 *	@cmd: the command
 *	@arg: command arg
 *	@uargs: UST arguments (internal)
 *	@owner: objd owner
 *
 *	This object descriptor implements lttng commands:
 *	LTTNG_UST_ABI_CONTEXT
 *		Prepend a context field to each record of events of this
 *		enabler.
 *	LTTNG_UST_ABI_ENABLE
 *		Enable recording for this enabler
 *	LTTNG_UST_ABI_DISABLE
 *		Disable recording for this enabler
 *	LTTNG_UST_ABI_FILTER
 *		Attach a filter to an enabler.
 *	LTTNG_UST_ABI_EXCLUSION
 *		Attach exclusions to an enabler.
 */
static
long lttng_event_enabler_cmd(int objd, unsigned int cmd, unsigned long arg,
	union lttng_ust_abi_args *uargs __attribute__((unused)),
	void *owner __attribute__((unused)))
{
	struct lttng_event_enabler_session_common *enabler = objd_private(objd);

	switch (cmd) {
	case LTTNG_UST_ABI_CONTEXT:
		return lttng_event_enabler_attach_context(enabler,
				(struct lttng_ust_abi_context *) arg);
	case LTTNG_UST_ABI_ENABLE:
		return lttng_event_enabler_enable(&enabler->parent);
	case LTTNG_UST_ABI_DISABLE:
		return lttng_event_enabler_disable(&enabler->parent);
	case LTTNG_UST_ABI_FILTER:
	{
		int ret;

		ret = lttng_event_enabler_attach_filter_bytecode(&enabler->parent,
				(struct lttng_ust_bytecode_node **) arg);
		if (ret)
			return ret;
		return 0;
	}
	case LTTNG_UST_ABI_EXCLUSION:
	{
		return lttng_event_enabler_attach_exclusion(&enabler->parent,
				(struct lttng_ust_excluder_node **) arg);
	}
	default:
		return -EINVAL;
	}
}

static
int lttng_event_enabler_release(int objd)
{
	struct lttng_event_recorder_enabler *event_enabler = objd_private(objd);

	if (event_enabler)
		return lttng_ust_abi_objd_unref(event_enabler->chan->priv->parent.objd, 0);

	return 0;
}

static const struct lttng_ust_abi_objd_ops lttng_event_enabler_ops = {
	.release = lttng_event_enabler_release,
	.cmd = lttng_event_enabler_cmd,
};

void lttng_ust_abi_exit(void)
{
	lttng_ust_abi_close_in_progress = 1;
	ust_lock_nocheck();
	objd_table_destroy();
	ust_unlock();
	lttng_ust_abi_close_in_progress = 0;
}
