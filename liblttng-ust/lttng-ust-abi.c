/*
 * lttng-ust-abi.c
 *
 * LTTng UST ABI
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
 *
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
#include <lttng/ust-abi.h>
#include <lttng/ust-error.h>
#include <urcu/compiler.h>
#include <urcu/list.h>
#include <lttng/ust-events.h>
#include <lttng/ust-version.h>
#include <lttng/tracepoint.h>
#include <ust-fd.h>
#include "tracepoint-internal.h"
#include <usterr-signal-safe.h>
#include <helper.h>
#include "lttng-tracer.h"
#include "string-utils.h"
#include "../libringbuffer/shm.h"
#include "../libringbuffer/frontend_types.h"

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

struct lttng_ust_obj {
	union {
		struct {
			void *private_data;
			const struct lttng_ust_objd_ops *ops;
			int f_count;
			int owner_ref;	/* has ref from owner */
			void *owner;
			char name[OBJ_NAME_LEN];
		} s;
		int freelist_next;	/* offset freelist. end is -1. */
	} u;
};

struct lttng_ust_objd_table {
	struct lttng_ust_obj *array;
	unsigned int len, allocated_len;
	int freelist_head;		/* offset freelist head. end is -1 */
};

static struct lttng_ust_objd_table objd_table = {
	.freelist_head = -1,
};

static
int objd_alloc(void *private_data, const struct lttng_ust_objd_ops *ops,
		void *owner, const char *name)
{
	struct lttng_ust_obj *obj;

	if (objd_table.freelist_head != -1) {
		obj = &objd_table.array[objd_table.freelist_head];
		objd_table.freelist_head = obj->u.freelist_next;
		goto end;
	}

	if (objd_table.len >= objd_table.allocated_len) {
		unsigned int new_allocated_len, old_allocated_len;
		struct lttng_ust_obj *new_table, *old_table;

		old_allocated_len = objd_table.allocated_len;
		old_table = objd_table.array;
		if (!old_allocated_len)
			new_allocated_len = 1;
		else
			new_allocated_len = old_allocated_len << 1;
		new_table = zmalloc(sizeof(struct lttng_ust_obj) * new_allocated_len);
		if (!new_table)
			return -ENOMEM;
		memcpy(new_table, old_table,
		       sizeof(struct lttng_ust_obj) * old_allocated_len);
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
struct lttng_ust_obj *_objd_get(int id)
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
	struct lttng_ust_obj *obj = _objd_get(id);
	assert(obj);
	return obj->u.s.private_data;
}

static
void objd_set_private(int id, void *private_data)
{
	struct lttng_ust_obj *obj = _objd_get(id);
	assert(obj);
	obj->u.s.private_data = private_data;
}

const struct lttng_ust_objd_ops *objd_ops(int id)
{
	struct lttng_ust_obj *obj = _objd_get(id);

	if (!obj)
		return NULL;
	return obj->u.s.ops;
}

static
void objd_free(int id)
{
	struct lttng_ust_obj *obj = _objd_get(id);

	assert(obj);
	obj->u.freelist_next = objd_table.freelist_head;
	objd_table.freelist_head = obj - objd_table.array;
	assert(obj->u.s.f_count == 1);
	obj->u.s.f_count = 0;	/* deallocated */
}

static
void objd_ref(int id)
{
	struct lttng_ust_obj *obj = _objd_get(id);
	assert(obj != NULL);
	obj->u.s.f_count++;
}

int lttng_ust_objd_unref(int id, int is_owner)
{
	struct lttng_ust_obj *obj = _objd_get(id);

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
		const struct lttng_ust_objd_ops *ops = objd_ops(id);

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
		struct lttng_ust_obj *obj;

		obj = _objd_get(i);
		if (!obj)
			continue;
		if (!obj->u.s.owner_ref)
			continue;	/* only unref owner ref. */
		(void) lttng_ust_objd_unref(i, 1);
	}
	free(objd_table.array);
	objd_table.array = NULL;
	objd_table.len = 0;
	objd_table.allocated_len = 0;
	objd_table.freelist_head = -1;
}

const char *lttng_ust_obj_get_name(int id)
{
	struct lttng_ust_obj *obj = _objd_get(id);

	if (!obj)
		return NULL;
	return obj->u.s.name;
}

void lttng_ust_objd_table_owner_cleanup(void *owner)
{
	int i;

	for (i = 0; i < objd_table.allocated_len; i++) {
		struct lttng_ust_obj *obj;

		obj = _objd_get(i);
		if (!obj)
			continue;
		if (!obj->u.s.owner)
			continue;	/* skip root handles */
		if (!obj->u.s.owner_ref)
			continue;	/* only unref owner ref. */
		if (obj->u.s.owner == owner)
			(void) lttng_ust_objd_unref(i, 1);
	}
}

/*
 * This is LTTng's own personal way to create an ABI for sessiond.
 * We send commands over a socket.
 */

static const struct lttng_ust_objd_ops lttng_ops;
static const struct lttng_ust_objd_ops lttng_session_ops;
static const struct lttng_ust_objd_ops lttng_channel_ops;
static const struct lttng_ust_objd_ops lttng_enabler_ops;
static const struct lttng_ust_objd_ops lttng_tracepoint_list_ops;
static const struct lttng_ust_objd_ops lttng_tracepoint_field_list_ops;

int lttng_abi_create_root_handle(void)
{
	int root_handle;

	/* root handles have NULL owners */
	root_handle = objd_alloc(NULL, &lttng_ops, NULL, "root");
	return root_handle;
}

static
int lttng_is_channel_ready(struct lttng_channel *lttng_chan)
{
	struct channel *chan;
	unsigned int nr_streams, exp_streams;

	chan = lttng_chan->chan;
	nr_streams = channel_handle_get_nr_streams(lttng_chan->handle);
	exp_streams = chan->nr_streams;
	return nr_streams == exp_streams;
}

static
int lttng_abi_create_session(void *owner)
{
	struct lttng_session *session;
	int session_objd, ret;

	session = lttng_session_create();
	if (!session)
		return -ENOMEM;
	session_objd = objd_alloc(session, &lttng_session_ops, owner, "session");
	if (session_objd < 0) {
		ret = session_objd;
		goto objd_error;
	}
	session->objd = session_objd;
	session->owner = owner;
	return session_objd;

objd_error:
	lttng_session_destroy(session);
	return ret;
}

static
long lttng_abi_tracer_version(int objd,
	struct lttng_ust_tracer_version *v)
{
	v->major = LTTNG_UST_MAJOR_VERSION;
	v->minor = LTTNG_UST_MINOR_VERSION;
	v->patchlevel = LTTNG_UST_PATCHLEVEL_VERSION;
	return 0;
}

static
long lttng_abi_add_context(int objd,
	struct lttng_ust_context *context_param,
	union ust_args *uargs,
	struct lttng_ctx **ctx, struct lttng_session *session)
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
 *	LTTNG_UST_SESSION
 *		Returns a LTTng trace session object descriptor
 *	LTTNG_UST_TRACER_VERSION
 *		Returns the LTTng kernel tracer version
 *	LTTNG_UST_TRACEPOINT_LIST
 *		Returns a file descriptor listing available tracepoints
 *	LTTNG_UST_TRACEPOINT_FIELD_LIST
 *		Returns a file descriptor listing available tracepoint fields
 *	LTTNG_UST_WAIT_QUIESCENT
 *		Returns after all previously running probes have completed
 *
 * The returned session will be deleted when its file descriptor is closed.
 */
static
long lttng_cmd(int objd, unsigned int cmd, unsigned long arg,
	union ust_args *uargs, void *owner)
{
	switch (cmd) {
	case LTTNG_UST_SESSION:
		return lttng_abi_create_session(owner);
	case LTTNG_UST_TRACER_VERSION:
		return lttng_abi_tracer_version(objd,
				(struct lttng_ust_tracer_version *) arg);
	case LTTNG_UST_TRACEPOINT_LIST:
		return lttng_abi_tracepoint_list(owner);
	case LTTNG_UST_TRACEPOINT_FIELD_LIST:
		return lttng_abi_tracepoint_field_list(owner);
	case LTTNG_UST_WAIT_QUIESCENT:
		synchronize_trace();
		return 0;
	default:
		return -EINVAL;
	}
}

static const struct lttng_ust_objd_ops lttng_ops = {
	.cmd = lttng_cmd,
};

int lttng_abi_map_channel(int session_objd,
		struct lttng_ust_channel *ust_chan,
		union ust_args *uargs,
		void *owner)
{
	struct lttng_session *session = objd_private(session_objd);
	const char *transport_name;
	const struct lttng_transport *transport;
	const char *chan_name;
	int chan_objd;
	struct lttng_ust_shm_handle *channel_handle;
	struct lttng_channel *lttng_chan;
	struct channel *chan;
	struct lttng_ust_lib_ring_buffer_config *config;
	void *chan_data;
	int wakeup_fd;
	uint64_t len;
	int ret;
	enum lttng_ust_chan_type type;

	chan_data = uargs->channel.chan_data;
	wakeup_fd = uargs->channel.wakeup_fd;
	len = ust_chan->len;
	type = ust_chan->type;

	switch (type) {
	case LTTNG_UST_CHAN_PER_CPU:
		break;
	default:
		ret = -EINVAL;
		goto invalid;
	}

	if (session->been_active) {
		ret = -EBUSY;
		goto active;	/* Refuse to add channel to active session */
	}

	channel_handle = channel_handle_create(chan_data, len, wakeup_fd);
	if (!channel_handle) {
		ret = -EINVAL;
		goto handle_error;
	}

	chan = shmp(channel_handle, channel_handle->chan);
	assert(chan);
	chan->handle = channel_handle;
	config = &chan->backend.config;
	lttng_chan = channel_get_private(chan);
	if (!lttng_chan) {
		ret = -EINVAL;
		goto alloc_error;
	}

	/* Lookup transport name */
	switch (type) {
	case LTTNG_UST_CHAN_PER_CPU:
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
	default:
		ret = -EINVAL;
		goto notransport;
	}
	transport = lttng_transport_find(transport_name);
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
	lttng_chan->chan = chan;
	lttng_chan->tstate = 1;
	lttng_chan->enabled = 1;
	lttng_chan->ctx = NULL;
	lttng_chan->session = session;
	lttng_chan->ops = &transport->ops;
	memcpy(&lttng_chan->chan->backend.config,
		transport->client_config,
		sizeof(lttng_chan->chan->backend.config));
	cds_list_add(&lttng_chan->node, &session->chan_head);
	lttng_chan->header_type = 0;
	lttng_chan->handle = channel_handle;
	lttng_chan->type = type;

	/*
	 * We tolerate no failure path after channel creation. It will stay
	 * invariant for the rest of the session.
	 */
	objd_set_private(chan_objd, lttng_chan);
	lttng_chan->objd = chan_objd;
	/* The channel created holds a reference on the session */
	objd_ref(session_objd);
	return chan_objd;

	/* error path after channel was created */
objd_error:
notransport:
alloc_error:
	channel_destroy(chan, channel_handle, 0);
	return ret;

	/*
	 * error path before channel creation (owning chan_data and
	 * wakeup_fd).
	 */
handle_error:
active:
invalid:
	{
		int close_ret;

		lttng_ust_lock_fd_tracker();
		close_ret = close(wakeup_fd);
		lttng_ust_unlock_fd_tracker();
		if (close_ret) {
			PERROR("close");
		}
	}
	free(chan_data);
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
 *	LTTNG_UST_CHANNEL
 *		Returns a LTTng channel object descriptor
 *	LTTNG_UST_ENABLE
 *		Enables tracing for a session (weak enable)
 *	LTTNG_UST_DISABLE
 *		Disables tracing for a session (strong disable)
 *
 * The returned channel will be deleted when its file descriptor is closed.
 */
static
long lttng_session_cmd(int objd, unsigned int cmd, unsigned long arg,
	union ust_args *uargs, void *owner)
{
	struct lttng_session *session = objd_private(objd);

	switch (cmd) {
	case LTTNG_UST_CHANNEL:
		return lttng_abi_map_channel(objd,
				(struct lttng_ust_channel *) arg,
				uargs, owner);
	case LTTNG_UST_SESSION_START:
	case LTTNG_UST_ENABLE:
		return lttng_session_enable(session);
	case LTTNG_UST_SESSION_STOP:
	case LTTNG_UST_DISABLE:
		return lttng_session_disable(session);
	case LTTNG_UST_SESSION_STATEDUMP:
		return lttng_session_statedump(session);
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
	struct lttng_session *session = objd_private(objd);

	if (session) {
		lttng_session_destroy(session);
		return 0;
	} else {
		return -EINVAL;
	}
}

static const struct lttng_ust_objd_ops lttng_session_ops = {
	.release = lttng_release_session,
	.cmd = lttng_session_cmd,
};

static
long lttng_tracepoint_list_cmd(int objd, unsigned int cmd, unsigned long arg,
	union ust_args *uargs, void *owner)
{
	struct lttng_ust_tracepoint_list *list = objd_private(objd);
	struct lttng_ust_tracepoint_iter *tp =
		(struct lttng_ust_tracepoint_iter *) arg;
	struct lttng_ust_tracepoint_iter *iter;

	switch (cmd) {
	case LTTNG_UST_TRACEPOINT_LIST_GET:
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

		err = lttng_ust_objd_unref(list_objd, 1);
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

static const struct lttng_ust_objd_ops lttng_tracepoint_list_ops = {
	.release = lttng_release_tracepoint_list,
	.cmd = lttng_tracepoint_list_cmd,
};

static
long lttng_tracepoint_field_list_cmd(int objd, unsigned int cmd,
	unsigned long arg, union ust_args *uargs, void *owner)
{
	struct lttng_ust_field_list *list = objd_private(objd);
	struct lttng_ust_field_iter *tp = &uargs->field_list.entry;
	struct lttng_ust_field_iter *iter;

	switch (cmd) {
	case LTTNG_UST_TRACEPOINT_FIELD_LIST_GET:
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

		err = lttng_ust_objd_unref(list_objd, 1);
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

static const struct lttng_ust_objd_ops lttng_tracepoint_field_list_ops = {
	.release = lttng_release_tracepoint_field_list,
	.cmd = lttng_tracepoint_field_list_cmd,
};

static
int lttng_abi_map_stream(int channel_objd, struct lttng_ust_stream *info,
		union ust_args *uargs, void *owner)
{
	struct lttng_channel *channel = objd_private(channel_objd);
	int ret;

	ret = channel_handle_add_stream(channel->handle,
		uargs->stream.shm_fd, uargs->stream.wakeup_fd,
		info->stream_nr, info->len);
	if (ret)
		goto error_add_stream;

	return 0;

error_add_stream:
	return ret;
}

static
int lttng_abi_create_enabler(int channel_objd,
			   struct lttng_ust_event *event_param,
			   void *owner,
			   enum lttng_enabler_type type)
{
	struct lttng_channel *channel = objd_private(channel_objd);
	struct lttng_enabler *enabler;
	int event_objd, ret;

	event_param->name[LTTNG_UST_SYM_NAME_LEN - 1] = '\0';
	event_objd = objd_alloc(NULL, &lttng_enabler_ops, owner, "enabler");
	if (event_objd < 0) {
		ret = event_objd;
		goto objd_error;
	}
	/*
	 * We tolerate no failure path after event creation. It will stay
	 * invariant for the rest of the session.
	 */
	enabler = lttng_enabler_create(type, event_param, channel);
	if (!enabler) {
		ret = -ENOMEM;
		goto event_error;
	}
	objd_set_private(event_objd, enabler);
	/* The event holds a reference on the channel */
	objd_ref(channel_objd);
	return event_objd;

event_error:
	{
		int err;

		err = lttng_ust_objd_unref(event_objd, 1);
		assert(!err);
	}
objd_error:
	return ret;
}

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
 *      LTTNG_UST_STREAM
 *              Returns an event stream object descriptor or failure.
 *              (typically, one event stream records events from one CPU)
 *	LTTNG_UST_EVENT
 *		Returns an event object descriptor or failure.
 *	LTTNG_UST_CONTEXT
 *		Prepend a context field to each event in the channel
 *	LTTNG_UST_ENABLE
 *		Enable recording for events in this channel (weak enable)
 *	LTTNG_UST_DISABLE
 *		Disable recording for events in this channel (strong disable)
 *
 * Channel and event file descriptors also hold a reference on the session.
 */
static
long lttng_channel_cmd(int objd, unsigned int cmd, unsigned long arg,
	union ust_args *uargs, void *owner)
{
	struct lttng_channel *channel = objd_private(objd);

	if (cmd != LTTNG_UST_STREAM) {
		/*
		 * Check if channel received all streams.
		 */
		if (!lttng_is_channel_ready(channel))
			return -EPERM;
	}

	switch (cmd) {
	case LTTNG_UST_STREAM:
	{
		struct lttng_ust_stream *stream;

		stream = (struct lttng_ust_stream *) arg;
		/* stream used as output */
		return lttng_abi_map_stream(objd, stream, uargs, owner);
	}
	case LTTNG_UST_EVENT:
	{
		struct lttng_ust_event *event_param =
			(struct lttng_ust_event *) arg;

		if (strutils_is_star_glob_pattern(event_param->name)) {
			/*
			 * If the event name is a star globbing pattern,
			 * we create the special star globbing enabler.
			 */
			return lttng_abi_create_enabler(objd, event_param,
					owner, LTTNG_ENABLER_STAR_GLOB);
		} else {
			return lttng_abi_create_enabler(objd, event_param,
					owner, LTTNG_ENABLER_EVENT);
		}
	}
	case LTTNG_UST_CONTEXT:
		return lttng_abi_add_context(objd,
				(struct lttng_ust_context *) arg, uargs,
				&channel->ctx, channel->session);
	case LTTNG_UST_ENABLE:
		return lttng_channel_enable(channel);
	case LTTNG_UST_DISABLE:
		return lttng_channel_disable(channel);
	case LTTNG_UST_FLUSH_BUFFER:
		return channel->ops->flush_buffer(channel->chan, channel->handle);
	default:
		return -EINVAL;
	}
}

static
int lttng_channel_release(int objd)
{
	struct lttng_channel *channel = objd_private(objd);

	if (channel)
		return lttng_ust_objd_unref(channel->session->objd, 0);
	return 0;
}

static const struct lttng_ust_objd_ops lttng_channel_ops = {
	.release = lttng_channel_release,
	.cmd = lttng_channel_cmd,
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
 *	LTTNG_UST_CONTEXT
 *		Prepend a context field to each record of events of this
 *		enabler.
 *	LTTNG_UST_ENABLE
 *		Enable recording for this enabler
 *	LTTNG_UST_DISABLE
 *		Disable recording for this enabler
 *	LTTNG_UST_FILTER
 *		Attach a filter to an enabler.
 *	LTTNG_UST_EXCLUSION
 *		Attach exclusions to an enabler.
 */
static
long lttng_enabler_cmd(int objd, unsigned int cmd, unsigned long arg,
	union ust_args *uargs, void *owner)
{
	struct lttng_enabler *enabler = objd_private(objd);

	switch (cmd) {
	case LTTNG_UST_CONTEXT:
		return lttng_enabler_attach_context(enabler,
				(struct lttng_ust_context *) arg);
	case LTTNG_UST_ENABLE:
		return lttng_enabler_enable(enabler);
	case LTTNG_UST_DISABLE:
		return lttng_enabler_disable(enabler);
	case LTTNG_UST_FILTER:
	{
		int ret;

		ret = lttng_enabler_attach_bytecode(enabler,
				(struct lttng_ust_filter_bytecode_node *) arg);
		if (ret)
			return ret;
		return 0;
	}
	case LTTNG_UST_EXCLUSION:
	{
		return lttng_enabler_attach_exclusion(enabler,
				(struct lttng_ust_excluder_node *) arg);
	}
	default:
		return -EINVAL;
	}
}

static
int lttng_enabler_release(int objd)
{
	struct lttng_enabler *enabler = objd_private(objd);

	if (enabler)
		return lttng_ust_objd_unref(enabler->chan->objd, 0);
	return 0;
}

static const struct lttng_ust_objd_ops lttng_enabler_ops = {
	.release = lttng_enabler_release,
	.cmd = lttng_enabler_cmd,
};

void lttng_ust_abi_exit(void)
{
	lttng_ust_abi_close_in_progress = 1;
	ust_lock_nocheck();
	objd_table_destroy();
	ust_unlock();
	lttng_ust_abi_close_in_progress = 0;
}
