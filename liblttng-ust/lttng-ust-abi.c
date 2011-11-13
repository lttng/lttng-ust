/*
 * lttng-ust-abi.c
 *
 * Copyright 2010-2011 (c) - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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
 *
 * Dual LGPL v2.1/GPL v2 license.
 */

#include <lttng/ust-abi.h>
#include <urcu/compiler.h>
#include <urcu/list.h>
#include <lttng/ust-events.h>
#include <lttng/usterr-signal-safe.h>
#include "lttng/core.h"
#include "ltt-tracer.h"

static int lttng_ust_abi_close_in_progress;

static
int lttng_abi_tracepoint_list(void);

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
int objd_alloc(void *private_data, const struct lttng_ust_objd_ops *ops)
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
	obj->u.s.f_count++;
}

int lttng_ust_objd_unref(int id)
{
	struct lttng_ust_obj *obj = _objd_get(id);

	if (!obj)
		return -EINVAL;
	if (obj->u.s.f_count == 1) {
		ERR("Reference counting error\n");
		return -EINVAL;
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

	for (i = 0; i < objd_table.allocated_len; i++)
		(void) lttng_ust_objd_unref(i);
	free(objd_table.array);
	objd_table.array = NULL;
	objd_table.len = 0;
	objd_table.allocated_len = 0;
	objd_table.freelist_head = -1;
}

/*
 * This is LTTng's own personal way to create an ABI for sessiond.
 * We send commands over a socket.
 */

static const struct lttng_ust_objd_ops lttng_ops;
static const struct lttng_ust_objd_ops lttng_session_ops;
static const struct lttng_ust_objd_ops lttng_channel_ops;
static const struct lttng_ust_objd_ops lttng_metadata_ops;
static const struct lttng_ust_objd_ops lttng_event_ops;
static const struct lttng_ust_objd_ops lib_ring_buffer_objd_ops;
static const struct lttng_ust_objd_ops lttng_tracepoint_list_ops;

enum channel_type {
	PER_CPU_CHANNEL,
	METADATA_CHANNEL,
};

int lttng_abi_create_root_handle(void)
{
	int root_handle;

	root_handle = objd_alloc(NULL, &lttng_ops);
	return root_handle;
}

static
int lttng_abi_create_session(void)
{
	struct ltt_session *session;
	int session_objd, ret;

	session = ltt_session_create();
	if (!session)
		return -ENOMEM;
	session_objd = objd_alloc(session, &lttng_session_ops);
	if (session_objd < 0) {
		ret = session_objd;
		goto objd_error;
	}
	session->objd = session_objd;
	return session_objd;

objd_error:
	ltt_session_destroy(session);
	return ret;
}

static
long lttng_abi_tracer_version(int objd,
	struct lttng_ust_tracer_version *v)
{
	v->version = LTTNG_UST_VERSION;
	v->patchlevel = LTTNG_UST_PATCHLEVEL;
	v->sublevel = LTTNG_UST_SUBLEVEL;
	return 0;
}

static
long lttng_abi_add_context(int objd,
	struct lttng_ust_context *context_param,
	struct lttng_ctx **ctx, struct ltt_session *session)
{
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

/**
 *	lttng_cmd - lttng control through socket commands
 *
 *	@objd: the object descriptor
 *	@cmd: the command
 *	@arg: command arg
 *
 *	This descriptor implements lttng commands:
 *	LTTNG_UST_SESSION
 *		Returns a LTTng trace session object descriptor
 *	LTTNG_UST_TRACER_VERSION
 *		Returns the LTTng kernel tracer version
 *	LTTNG_UST_TRACEPOINT_LIST
 *		Returns a file descriptor listing available tracepoints
 *	LTTNG_UST_WAIT_QUIESCENT
 *		Returns after all previously running probes have completed
 *
 * The returned session will be deleted when its file descriptor is closed.
 */
static
long lttng_cmd(int objd, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case LTTNG_UST_SESSION:
		return lttng_abi_create_session();
	case LTTNG_UST_TRACER_VERSION:
		return lttng_abi_tracer_version(objd,
				(struct lttng_ust_tracer_version *) arg);
	case LTTNG_UST_TRACEPOINT_LIST:
		return lttng_abi_tracepoint_list();
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

/*
 * We tolerate no failure in this function (if one happens, we print a dmesg
 * error, but cannot return any error, because the channel information is
 * invariant.
 */
static
void lttng_metadata_create_events(int channel_objd)
{
	struct ltt_channel *channel = objd_private(channel_objd);
	static struct lttng_ust_event metadata_params = {
		.instrumentation = LTTNG_UST_TRACEPOINT,
		.name = "lttng_ust:metadata",
	};
	struct ltt_event *event;

	/*
	 * We tolerate no failure path after event creation. It will stay
	 * invariant for the rest of the session.
	 */
	event = ltt_event_create(channel, &metadata_params, NULL);
	if (!event) {
		goto create_error;
	}
	return;

create_error:
	WARN_ON(1);
	return;		/* not allowed to return error */
}

int lttng_abi_create_channel(int session_objd,
			     struct lttng_ust_channel *chan_param,
			     enum channel_type channel_type)
{
	struct ltt_session *session = objd_private(session_objd);
	const struct lttng_ust_objd_ops *ops;
	const char *transport_name;
	struct ltt_channel *chan;
	int chan_objd;
	int ret = 0;
	struct ltt_channel chan_priv_init;

	switch (channel_type) {
	case PER_CPU_CHANNEL:
		if (chan_param->output == LTTNG_UST_MMAP) {
			transport_name = chan_param->overwrite ?
				"relay-overwrite-mmap" : "relay-discard-mmap";
		} else {
			return -EINVAL;
		}
		ops = &lttng_channel_ops;
		break;
	case METADATA_CHANNEL:
		if (chan_param->output == LTTNG_UST_MMAP)
			transport_name = "relay-metadata-mmap";
		else
			return -EINVAL;
		ops = &lttng_metadata_ops;
		break;
	default:
		transport_name = "<unknown>";
		return -EINVAL;
	}
	chan_objd = objd_alloc(NULL, ops);
	if (chan_objd < 0) {
		ret = chan_objd;
		goto objd_error;
	}
	memset(&chan_priv_init, 0, sizeof(chan_priv_init));
	/* Copy of session UUID for consumer (availability through shm) */
	memcpy(chan_priv_init.uuid, session->uuid, sizeof(session->uuid));
	
	/*
	 * We tolerate no failure path after channel creation. It will stay
	 * invariant for the rest of the session.
	 */
	chan = ltt_channel_create(session, transport_name, NULL,
				  chan_param->subbuf_size,
				  chan_param->num_subbuf,
				  chan_param->switch_timer_interval,
				  chan_param->read_timer_interval,
				  &chan_param->shm_fd,
				  &chan_param->wait_fd,
				  &chan_param->memory_map_size,
				  &chan_priv_init);
	if (!chan) {
		ret = -EINVAL;
		goto chan_error;
	}
	objd_set_private(chan_objd, chan);
	chan->objd = chan_objd;
	if (channel_type == METADATA_CHANNEL) {
		session->metadata = chan;
		lttng_metadata_create_events(chan_objd);
	}
	/* The channel created holds a reference on the session */
	objd_ref(session_objd);

	return chan_objd;

chan_error:
	{
		int err;

		err = lttng_ust_objd_unref(chan_objd);
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
 *
 *	This descriptor implements lttng commands:
 *	LTTNG_UST_CHANNEL
 *		Returns a LTTng channel object descriptor
 *	LTTNG_UST_ENABLE
 *		Enables tracing for a session (weak enable)
 *	LTTNG_UST_DISABLE
 *		Disables tracing for a session (strong disable)
 *	LTTNG_UST_METADATA
 *		Returns a LTTng metadata object descriptor
 *
 * The returned channel will be deleted when its file descriptor is closed.
 */
static
long lttng_session_cmd(int objd, unsigned int cmd, unsigned long arg)
{
	struct ltt_session *session = objd_private(objd);

	switch (cmd) {
	case LTTNG_UST_CHANNEL:
		return lttng_abi_create_channel(objd,
				(struct lttng_ust_channel *) arg,
				PER_CPU_CHANNEL);
	case LTTNG_UST_SESSION_START:
	case LTTNG_UST_ENABLE:
		return ltt_session_enable(session);
	case LTTNG_UST_SESSION_STOP:
	case LTTNG_UST_DISABLE:
		return ltt_session_disable(session);
	case LTTNG_UST_METADATA:
		return lttng_abi_create_channel(objd,
				(struct lttng_ust_channel *) arg,
				METADATA_CHANNEL);
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
	struct ltt_session *session = objd_private(objd);

	if (session) {
		ltt_session_destroy(session);
		return 0;
	} else {
		return -EINVAL;
	}
}

static const struct lttng_ust_objd_ops lttng_session_ops = {
	.release = lttng_release_session,
	.cmd = lttng_session_cmd,
};

/*
 * beware: we don't keep the mutex over the send, but we must walk the
 * whole list each time we are called again. So sending one tracepoint
 * at a time means this is O(n^2). TODO: do as in the kernel and send
 * multiple tracepoints for each call to amortize this cost.
 */
static
void ltt_tracepoint_list_get(struct ltt_tracepoint_list *list,
		char *tp_list_entry)
{
next:
	if (!list->got_first) {
		tracepoint_iter_start(&list->iter);
		list->got_first = 1;
		goto copy;
	}
	tracepoint_iter_next(&list->iter);
copy:
	if (!list->iter.tracepoint) {
		tp_list_entry[0] = '\0';	/* end of list */
	} else {
		if (!strcmp((*list->iter.tracepoint)->name,
				"lttng_ust:metadata"))
			goto next;
		memcpy(tp_list_entry, (*list->iter.tracepoint)->name,
			LTTNG_UST_SYM_NAME_LEN);
	}
}

static
long lttng_tracepoint_list_cmd(int objd, unsigned int cmd, unsigned long arg)
{
	struct ltt_tracepoint_list *list = objd_private(objd);
	char *str = (char *) arg;

	switch (cmd) {
	case LTTNG_UST_TRACEPOINT_LIST_GET:
		ltt_tracepoint_list_get(list, str);
		if (str[0] == '\0')
			return -ENOENT;
		return 0;
	default:
		return -EINVAL;
	}
}

static
int lttng_abi_tracepoint_list(void)
{
	int list_objd, ret;
	struct ltt_tracepoint_list *list;

	list_objd = objd_alloc(NULL, &lttng_tracepoint_list_ops);
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

	return list_objd;

alloc_error:
	{
		int err;

		err = lttng_ust_objd_unref(list_objd);
		assert(!err);
	}
objd_error:
	return ret;
}

static
int lttng_release_tracepoint_list(int objd)
{
	struct ltt_tracepoint_list *list = objd_private(objd);

	if (list) {
		tracepoint_iter_stop(&list->iter);
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

struct stream_priv_data {
	struct lttng_ust_lib_ring_buffer *buf;
	struct ltt_channel *ltt_chan;
};

static
int lttng_abi_open_stream(int channel_objd, struct lttng_ust_stream *info)
{
	struct ltt_channel *channel = objd_private(channel_objd);
	struct lttng_ust_lib_ring_buffer *buf;
	struct stream_priv_data *priv;
	int stream_objd, ret;

	buf = channel->ops->buffer_read_open(channel->chan, channel->handle,
			&info->shm_fd, &info->wait_fd, &info->memory_map_size);
	if (!buf)
		return -ENOENT;

	priv = zmalloc(sizeof(*priv));
	if (!priv) {
		ret = -ENOMEM;
		goto alloc_error;
	}
	priv->buf = buf;
	priv->ltt_chan = channel;
	stream_objd = objd_alloc(priv, &lib_ring_buffer_objd_ops);
	if (stream_objd < 0) {
		ret = stream_objd;
		goto objd_error;
	}
	/* Hold a reference on the channel object descriptor */
	objd_ref(channel_objd);
	return stream_objd;

objd_error:
	free(priv);
alloc_error:
	channel->ops->buffer_read_close(buf, channel->handle);
	return ret;
}

static
int lttng_abi_create_event(int channel_objd,
			   struct lttng_ust_event *event_param)
{
	struct ltt_channel *channel = objd_private(channel_objd);
	struct ltt_event *event;
	int event_objd, ret;

	event_param->name[LTTNG_UST_SYM_NAME_LEN - 1] = '\0';
	event_objd = objd_alloc(NULL, &lttng_event_ops);
	if (event_objd < 0) {
		ret = event_objd;
		goto objd_error;
	}
	/*
	 * We tolerate no failure path after event creation. It will stay
	 * invariant for the rest of the session.
	 */
	event = ltt_event_create(channel, event_param, NULL);
	if (!event) {
		ret = -EINVAL;
		goto event_error;
	}
	objd_set_private(event_objd, event);
	/* The event holds a reference on the channel */
	objd_ref(channel_objd);
	return event_objd;

event_error:
	{
		int err;

		err = lttng_ust_objd_unref(event_objd);
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
long lttng_channel_cmd(int objd, unsigned int cmd, unsigned long arg)
{
	struct ltt_channel *channel = objd_private(objd);

	switch (cmd) {
	case LTTNG_UST_STREAM:
	{
		struct lttng_ust_stream *stream;

		stream = (struct lttng_ust_stream *) arg;
		/* stream used as output */
		return lttng_abi_open_stream(objd, stream);
	}
	case LTTNG_UST_EVENT:
		return lttng_abi_create_event(objd, (struct lttng_ust_event *) arg);
	case LTTNG_UST_CONTEXT:
		return lttng_abi_add_context(objd,
				(struct lttng_ust_context *) arg,
				&channel->ctx, channel->session);
	case LTTNG_UST_ENABLE:
		return ltt_channel_enable(channel);
	case LTTNG_UST_DISABLE:
		return ltt_channel_disable(channel);
	case LTTNG_UST_FLUSH_BUFFER:
		return channel->ops->flush_buffer(channel->chan, channel->handle);
	default:
		return -EINVAL;
	}
}

/**
 *	lttng_metadata_cmd - lttng control through object descriptors
 *
 *	@objd: the object descriptor
 *	@cmd: the command
 *	@arg: command arg
 *
 *	This object descriptor implements lttng commands:
 *      LTTNG_UST_STREAM
 *              Returns an event stream file descriptor or failure.
 *
 * Channel and event file descriptors also hold a reference on the session.
 */
static
long lttng_metadata_cmd(int objd, unsigned int cmd, unsigned long arg)
{
	struct ltt_channel *channel = objd_private(objd);

	switch (cmd) {
	case LTTNG_UST_STREAM:
	{
		struct lttng_ust_stream *stream;

		stream = (struct lttng_ust_stream *) arg;
		/* stream used as output */
		return lttng_abi_open_stream(objd, stream);
	}
	case LTTNG_UST_FLUSH_BUFFER:
		return channel->ops->flush_buffer(channel->chan, channel->handle);
	default:
		return -EINVAL;
	}
}

#if 0
/**
 *	lttng_channel_poll - lttng stream addition/removal monitoring
 *
 *	@file: the file
 *	@wait: poll table
 */
unsigned int lttng_channel_poll(struct file *file, poll_table *wait)
{
	struct ltt_channel *channel = file->private_data;
	unsigned int mask = 0;

	if (file->f_mode & FMODE_READ) {
		poll_wait_set_exclusive(wait);
		poll_wait(file, channel->ops->get_hp_wait_queue(channel->chan),
			  wait);

		if (channel->ops->is_disabled(channel->chan))
			return POLLERR;
		if (channel->ops->is_finalized(channel->chan))
			return POLLHUP;
		if (channel->ops->buffer_has_read_closed_stream(channel->chan))
			return POLLIN | POLLRDNORM;
		return 0;
	}
	return mask;

}
#endif //0

static
int lttng_channel_release(int objd)
{
	struct ltt_channel *channel = objd_private(objd);

	if (channel)
		return lttng_ust_objd_unref(channel->session->objd);
	return 0;
}

static const struct lttng_ust_objd_ops lttng_channel_ops = {
	.release = lttng_channel_release,
	//.poll = lttng_channel_poll,
	.cmd = lttng_channel_cmd,
};

static const struct lttng_ust_objd_ops lttng_metadata_ops = {
	.release = lttng_channel_release,
	.cmd = lttng_metadata_cmd,
};

/**
 *	lttng_rb_cmd - lttng ring buffer control through object descriptors
 *
 *	@objd: the object descriptor
 *	@cmd: the command
 *	@arg: command arg
 *
 *	This object descriptor implements lttng commands:
 *		(None for now. Access is done directly though shm.)
 */
static
long lttng_rb_cmd(int objd, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	default:
		return -EINVAL;
	}
}

static
int lttng_rb_release(int objd)
{
	struct stream_priv_data *priv = objd_private(objd);
	struct lttng_ust_lib_ring_buffer *buf;
	struct ltt_channel *channel;

	if (priv) {
		buf = priv->buf;
		channel = priv->ltt_chan;
		free(priv);
		/*
		 * If we are at ABI exit, we don't want to close the
		 * buffer opened for read: it is being shared between
		 * the parent and child (right after fork), and we don't
		 * want the child to close it for the parent. For a real
		 * exit, we don't care about marking it as closed, as
		 * the consumer daemon (if there is one) will do fine
		 * even if we don't mark it as "closed" for reading on
		 * our side.
		 * We only mark it as closed if it is being explicitely
		 * released by the session daemon with an explicit
		 * release command.
		 */
		if (!lttng_ust_abi_close_in_progress)
			channel->ops->buffer_read_close(buf, channel->handle);

		return lttng_ust_objd_unref(channel->objd);
	}
	return 0;
}

static const struct lttng_ust_objd_ops lib_ring_buffer_objd_ops = {
	.release = lttng_rb_release,
	.cmd = lttng_rb_cmd,
};

/**
 *	lttng_event_cmd - lttng control through object descriptors
 *
 *	@objd: the object descriptor
 *	@cmd: the command
 *	@arg: command arg
 *
 *	This object descriptor implements lttng commands:
 *	LTTNG_UST_CONTEXT
 *		Prepend a context field to each record of this event
 *	LTTNG_UST_ENABLE
 *		Enable recording for this event (weak enable)
 *	LTTNG_UST_DISABLE
 *		Disable recording for this event (strong disable)
 */
static
long lttng_event_cmd(int objd, unsigned int cmd, unsigned long arg)
{
	struct ltt_event *event = objd_private(objd);

	switch (cmd) {
	case LTTNG_UST_CONTEXT:
		return lttng_abi_add_context(objd,
				(struct lttng_ust_context *) arg,
				&event->ctx, event->chan->session);
	case LTTNG_UST_ENABLE:
		return ltt_event_enable(event);
	case LTTNG_UST_DISABLE:
		return ltt_event_disable(event);
	default:
		return -EINVAL;
	}
}

static
int lttng_event_release(int objd)
{
	struct ltt_event *event = objd_private(objd);

	if (event)
		return lttng_ust_objd_unref(event->chan->objd);
	return 0;
}

/* TODO: filter control ioctl */
static const struct lttng_ust_objd_ops lttng_event_ops = {
	.release = lttng_event_release,
	.cmd = lttng_event_cmd,
};

void lttng_ust_abi_exit(void)
{
	lttng_ust_abi_close_in_progress = 1;
	objd_table_destroy();
	lttng_ust_abi_close_in_progress = 0;
}
