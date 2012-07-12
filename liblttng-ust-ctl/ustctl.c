/*
 * Copyright (C) 2011 - Julien Desfossez <julien.desfossez@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License only.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _GNU_SOURCE
#include <string.h>
#include <lttng/ust-ctl.h>
#include <lttng/ust-abi.h>
#include <lttng/ust-events.h>
#include <sys/mman.h>

#include <usterr-signal-safe.h>
#include <ust-comm.h>

#include "../libringbuffer/backend.h"
#include "../libringbuffer/frontend.h"

volatile enum ust_loglevel ust_loglevel;

static
void init_object(struct lttng_ust_object_data *data)
{
	data->handle = -1;
	data->shm_fd = -1;
	data->wait_fd = -1;
	data->memory_map_size = 0;
}

int ustctl_release_handle(int sock, int handle)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret;

	if (sock >= 0) {
		memset(&lum, 0, sizeof(lum));
		lum.handle = handle;
		lum.cmd = LTTNG_UST_RELEASE;
		ret = ustcomm_send_app_cmd(sock, &lum, &lur);
		if (ret < 0) {
			return ret;
		}
	}
	return 0;
}
/*
 * If sock is negative, it means we don't have to notify the other side
 * (e.g. application has already vanished).
 */
int ustctl_release_object(int sock, struct lttng_ust_object_data *data)
{
	int ret;

	if (!data)
		return -EINVAL;

	if (data->shm_fd >= 0) {
		ret = close(data->shm_fd);
		if (ret < 0) {
			return ret;
		}
	}
	if (data->wait_fd >= 0) {
		ret = close(data->wait_fd);
		if (ret < 0) {
			return ret;
		}
	}
	return ustctl_release_handle(sock, data->handle);
}

/*
 * Send registration done packet to the application.
 */
int ustctl_register_done(int sock)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret;

	DBG("Sending register done command to %d", sock);
	memset(&lum, 0, sizeof(lum));
	lum.handle = LTTNG_UST_ROOT_HANDLE;
	lum.cmd = LTTNG_UST_REGISTER_DONE;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	if (lur.ret_code != USTCOMM_OK) {
		DBG("Return code: %s", ustcomm_get_readable_code(lur.ret_code));
		goto error;
	}
	return 0;

error:
	return -1;
}

/*
 * returns session handle.
 */
int ustctl_create_session(int sock)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret, session_handle;

	/* Create session */
	memset(&lum, 0, sizeof(lum));
	lum.handle = LTTNG_UST_ROOT_HANDLE;
	lum.cmd = LTTNG_UST_SESSION;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	session_handle = lur.ret_val;
	DBG("received session handle %u", session_handle);
	return session_handle;
}

/* open the metadata global channel */
int ustctl_open_metadata(int sock, int session_handle,
		struct lttng_ust_channel_attr *chops,
		struct lttng_ust_object_data **_metadata_data)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	struct lttng_ust_object_data *metadata_data;
	int ret, err = 0;

	if (!chops || !_metadata_data)
		return -EINVAL;

	metadata_data = malloc(sizeof(*metadata_data));
	if (!metadata_data)
		return -ENOMEM;
	init_object(metadata_data);
	/* Create metadata channel */
	memset(&lum, 0, sizeof(lum));
	lum.handle = session_handle;
	lum.cmd = LTTNG_UST_METADATA;
	lum.u.channel.overwrite = chops->overwrite;
	lum.u.channel.subbuf_size = chops->subbuf_size;
	lum.u.channel.num_subbuf = chops->num_subbuf;
	lum.u.channel.switch_timer_interval = chops->switch_timer_interval;
	lum.u.channel.read_timer_interval = chops->read_timer_interval;
	lum.u.channel.output = chops->output;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret) {
		free(metadata_data);
		return ret;
	}
	if (lur.ret_code != USTCOMM_OK) {
		free(metadata_data);
		return lur.ret_code;
	}
	metadata_data->handle = lur.ret_val;
	DBG("received metadata handle %u", metadata_data->handle);
	metadata_data->memory_map_size = lur.u.channel.memory_map_size;
	/* get shm fd */
	ret = ustcomm_recv_fd(sock);
	if (ret < 0)
		err = 1;
	else
		metadata_data->shm_fd = ret;
	/*
	 * We need to get the second FD even if the first fails, because
	 * libust expects us to read the two FDs.
	 */
	/* get wait fd */
	ret = ustcomm_recv_fd(sock);
	if (ret < 0)
		err = 1;
	else
		metadata_data->wait_fd = ret;
	if (err)
		goto error;
	*_metadata_data = metadata_data;
	return 0;

error:
	(void) ustctl_release_object(sock, metadata_data);
	free(metadata_data);
	return -EINVAL;
}

int ustctl_create_channel(int sock, int session_handle,
		struct lttng_ust_channel_attr *chops,
		struct lttng_ust_object_data **_channel_data)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	struct lttng_ust_object_data *channel_data;
	int ret, err = 0;

	if (!chops || !_channel_data)
		return -EINVAL;

	channel_data = malloc(sizeof(*channel_data));
	if (!channel_data)
		return -ENOMEM;
	init_object(channel_data);
	/* Create metadata channel */
	memset(&lum, 0, sizeof(lum));
	lum.handle = session_handle;
	lum.cmd = LTTNG_UST_CHANNEL;
	lum.u.channel.overwrite = chops->overwrite;
	lum.u.channel.subbuf_size = chops->subbuf_size;
	lum.u.channel.num_subbuf = chops->num_subbuf;
	lum.u.channel.switch_timer_interval = chops->switch_timer_interval;
	lum.u.channel.read_timer_interval = chops->read_timer_interval;
	lum.u.channel.output = chops->output;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret) {
		free(channel_data);
		return ret;
	}
	if (lur.ret_code != USTCOMM_OK) {
		free(channel_data);
		return lur.ret_code;
	}
	channel_data->handle = lur.ret_val;
	DBG("received channel handle %u", channel_data->handle);
	channel_data->memory_map_size = lur.u.channel.memory_map_size;
	/* get shm fd */
	ret = ustcomm_recv_fd(sock);
	if (ret < 0)
		err = 1;
	else
		channel_data->shm_fd = ret;
	/*
	 * We need to get the second FD even if the first fails, because
	 * libust expects us to read the two FDs.
	 */
	/* get wait fd */
	ret = ustcomm_recv_fd(sock);
	if (ret < 0)
		err = 1;
	else
		channel_data->wait_fd = ret;
	if (err)
		goto error;
	*_channel_data = channel_data;
	return 0;

error:
	(void) ustctl_release_object(sock, channel_data);
	free(channel_data);
	return -EINVAL;
}

/*
 * Return -ENOENT if no more stream is available for creation.
 * Return 0 on success.
 * Return negative error value on error.
 */
int ustctl_create_stream(int sock, struct lttng_ust_object_data *channel_data,
		struct lttng_ust_object_data **_stream_data)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	struct lttng_ust_object_data *stream_data;
	int ret, fd, err = 0;

	if (!channel_data || !_stream_data)
		return -EINVAL;

	stream_data = malloc(sizeof(*stream_data));
	if (!stream_data)
		return -ENOMEM;
	init_object(stream_data);
	memset(&lum, 0, sizeof(lum));
	lum.handle = channel_data->handle;
	lum.cmd = LTTNG_UST_STREAM;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret) {
		free(stream_data);
		return ret;
	}
	if (lur.ret_code != USTCOMM_OK) {
		free(stream_data);
		return lur.ret_code;
	}

	stream_data->handle = lur.ret_val;
	DBG("received stream handle %u", stream_data->handle);
	stream_data->memory_map_size = lur.u.stream.memory_map_size;
	/* get shm fd */
	fd = ustcomm_recv_fd(sock);
	if (fd < 0)
		err = 1;
	else
		stream_data->shm_fd = fd;
	/*
	 * We need to get the second FD even if the first fails, because
	 * libust expects us to read the two FDs.
	 */
	/* get wait fd */
	fd = ustcomm_recv_fd(sock);
	if (fd < 0)
		err = 1;
	else
		stream_data->wait_fd = fd;
	if (err)
		goto error;
	*_stream_data = stream_data;
	return ret;

error:
	(void) ustctl_release_object(sock, stream_data);
	free(stream_data);
	return -EINVAL;
}

int ustctl_create_event(int sock, struct lttng_ust_event *ev,
		struct lttng_ust_object_data *channel_data,
		struct lttng_ust_object_data **_event_data)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	struct lttng_ust_object_data *event_data;
	int ret;

	if (!channel_data || !_event_data)
		return -EINVAL;

	event_data = malloc(sizeof(*event_data));
	if (!event_data)
		return -ENOMEM;
	init_object(event_data);
	memset(&lum, 0, sizeof(lum));
	lum.handle = channel_data->handle;
	lum.cmd = LTTNG_UST_EVENT;
	strncpy(lum.u.event.name, ev->name,
		LTTNG_UST_SYM_NAME_LEN);
	lum.u.event.instrumentation = ev->instrumentation;
	lum.u.event.loglevel_type = ev->loglevel_type;
	lum.u.event.loglevel = ev->loglevel;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret) {
		free(event_data);
		return ret;
	}
	event_data->handle = lur.ret_val;
	DBG("received event handle %u", event_data->handle);
	*_event_data = event_data;
	return 0;
}

int ustctl_add_context(int sock, struct lttng_ust_context *ctx,
		struct lttng_ust_object_data *obj_data,
		struct lttng_ust_object_data **_context_data)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	struct lttng_ust_object_data *context_data;
	int ret;

	if (!obj_data || !_context_data)
		return -EINVAL;

	context_data = malloc(sizeof(*context_data));
	if (!context_data)
		return -ENOMEM;
	init_object(context_data);
	memset(&lum, 0, sizeof(lum));
	lum.handle = obj_data->handle;
	lum.cmd = LTTNG_UST_CONTEXT;
	lum.u.context.ctx = ctx->ctx;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret) {
		free(context_data);
		return ret;
	}
	context_data->handle = lur.ret_val;
	DBG("received context handle %u", context_data->handle);
	*_context_data = context_data;
	return ret;
}

int ustctl_set_filter(int sock, struct lttng_ust_filter_bytecode *bytecode,
		struct lttng_ust_object_data *obj_data)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret;

	if (!obj_data)
		return -EINVAL;

	memset(&lum, 0, sizeof(lum));
	lum.handle = obj_data->handle;
	lum.cmd = LTTNG_UST_FILTER;
	lum.u.filter.data_size = bytecode->len;
	lum.u.filter.reloc_offset = bytecode->reloc_offset;

	ret = ustcomm_send_app_msg(sock, &lum);
	if (ret)
		return ret;
	if (ret) {
		return ret;
	}
	/* send var len bytecode */
	ret = ustcomm_send_unix_sock(sock, bytecode->data,
				bytecode->len);
	if (ret < 0) {
		return ret;
	}
	ret = ustcomm_recv_app_reply(sock, &lur, lum.handle, lum.cmd);
	if (ret)
		return ret;
	return ret;
}

/* Enable event, channel and session ioctl */
int ustctl_enable(int sock, struct lttng_ust_object_data *object)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret;

	if (!object)
		return -EINVAL;

	memset(&lum, 0, sizeof(lum));
	lum.handle = object->handle;
	lum.cmd = LTTNG_UST_ENABLE;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	DBG("enabled handle %u", object->handle);
	return 0;
}

/* Disable event, channel and session ioctl */
int ustctl_disable(int sock, struct lttng_ust_object_data *object)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret;

	if (!object)
		return -EINVAL;

	memset(&lum, 0, sizeof(lum));
	lum.handle = object->handle;
	lum.cmd = LTTNG_UST_DISABLE;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	DBG("disable handle %u", object->handle);
	return 0;
}

int ustctl_start_session(int sock, int handle)
{
	struct lttng_ust_object_data obj;

	obj.handle = handle;
	return ustctl_enable(sock, &obj);
}

int ustctl_stop_session(int sock, int handle)
{
	struct lttng_ust_object_data obj;

	obj.handle = handle;
	return ustctl_disable(sock, &obj);
}

int ustctl_tracepoint_list(int sock)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret, tp_list_handle;

	memset(&lum, 0, sizeof(lum));
	lum.handle = LTTNG_UST_ROOT_HANDLE;
	lum.cmd = LTTNG_UST_TRACEPOINT_LIST;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	tp_list_handle = lur.ret_val;
	DBG("received tracepoint list handle %u", tp_list_handle);
	return tp_list_handle;
}

int ustctl_tracepoint_list_get(int sock, int tp_list_handle,
		struct lttng_ust_tracepoint_iter *iter)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret;

	if (!iter)
		return -EINVAL;

	memset(&lum, 0, sizeof(lum));
	lum.handle = tp_list_handle;
	lum.cmd = LTTNG_UST_TRACEPOINT_LIST_GET;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	DBG("received tracepoint list entry name %s loglevel %d",
		lur.u.tracepoint.name,
		lur.u.tracepoint.loglevel);
	memcpy(iter, &lur.u.tracepoint, sizeof(*iter));
	return 0;
}

int ustctl_tracepoint_field_list(int sock)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret, tp_field_list_handle;

	memset(&lum, 0, sizeof(lum));
	lum.handle = LTTNG_UST_ROOT_HANDLE;
	lum.cmd = LTTNG_UST_TRACEPOINT_FIELD_LIST;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	tp_field_list_handle = lur.ret_val;
	DBG("received tracepoint field list handle %u", tp_field_list_handle);
	return tp_field_list_handle;
}

int ustctl_tracepoint_field_list_get(int sock, int tp_field_list_handle,
		struct lttng_ust_field_iter *iter)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret;
	ssize_t len;

	if (!iter)
		return -EINVAL;

	memset(&lum, 0, sizeof(lum));
	lum.handle = tp_field_list_handle;
	lum.cmd = LTTNG_UST_TRACEPOINT_FIELD_LIST_GET;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	if (lur.ret_code != USTCOMM_OK) {
		DBG("Return code: %s", ustcomm_get_readable_code(lur.ret_code));
		return -EINVAL;
	}
	len = ustcomm_recv_unix_sock(sock, iter, sizeof(*iter));
	if (len != sizeof(*iter)) {
		return -EINVAL;
	}
	DBG("received tracepoint field list entry event_name %s event_loglevel %d field_name %s field_type %d",
		iter->event_name,
		iter->loglevel,
		iter->field_name,
		iter->type);
	return 0;
}

int ustctl_tracer_version(int sock, struct lttng_ust_tracer_version *v)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret;

	if (!v)
		return -EINVAL;

	memset(&lum, 0, sizeof(lum));
	lum.handle = LTTNG_UST_ROOT_HANDLE;
	lum.cmd = LTTNG_UST_TRACER_VERSION;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	memcpy(v, &lur.u.version, sizeof(*v));
	DBG("received tracer version");
	return 0;
}

int ustctl_wait_quiescent(int sock)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret;

	memset(&lum, 0, sizeof(lum));
	lum.handle = LTTNG_UST_ROOT_HANDLE;
	lum.cmd = LTTNG_UST_WAIT_QUIESCENT;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	DBG("waited for quiescent state");
	return 0;
}

int ustctl_calibrate(int sock, struct lttng_ust_calibrate *calibrate)
{
	if (!calibrate)
		return -EINVAL;

	return -ENOSYS;
}

int ustctl_sock_flush_buffer(int sock, struct lttng_ust_object_data *object)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret;

	if (!object)
		return -EINVAL;

	memset(&lum, 0, sizeof(lum));
	lum.handle = object->handle;
	lum.cmd = LTTNG_UST_FLUSH_BUFFER;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	DBG("flushed buffer handle %u", object->handle);
	return 0;
}

/* Buffer operations */

/* Map channel shm into process memory */
struct lttng_ust_shm_handle *ustctl_map_channel(struct lttng_ust_object_data *chan_data)
{
	struct lttng_ust_shm_handle *handle;
	struct channel *chan;
	size_t chan_size;
	struct lttng_ust_lib_ring_buffer_config *config;
	int ret;

	if (!chan_data)
		return NULL;

	handle = channel_handle_create(chan_data->shm_fd,
		chan_data->wait_fd,
		chan_data->memory_map_size);
	if (!handle) {
		ERR("create handle error");
		return NULL;
	}
	/*
	 * Set to -1, and then close the shm fd, and set the handle shm
	 * fd to -1 too. We don't need the shm fds after they have been
	 * mapped.
	 * The wait_fd is set to -1 in chan_data because it is now owned
	 * by the handle.
	 */
	chan_data->shm_fd = -1;
	chan_data->wait_fd = -1;

	/* chan is object 0. This is hardcoded. */
	if (handle->table->objects[0].shm_fd >= 0) {
		ret = close(handle->table->objects[0].shm_fd);
		if (ret) {
			perror("Error closing shm_fd");
		}
		handle->table->objects[0].shm_fd = -1;
	}

	/*
	 * TODO: add consistency checks to be resilient if the
	 * application try to feed us with incoherent channel structure
	 * values.
	 */
	chan = shmp(handle, handle->chan);
	/* chan is object 0. This is hardcoded. */
	chan_size = handle->table->objects[0].allocated_len;
	handle->shadow_chan = malloc(chan_size);
	if (!handle->shadow_chan) {
		channel_destroy(chan, handle, 1);
		return NULL;
	}
	memcpy(handle->shadow_chan, chan, chan_size);
	/*
	 * The callback pointers in the producer are invalid in the
	 * consumer. We need to look them up here.
	 */
	config = &handle->shadow_chan->backend.config;
	switch (config->client_type) {
	case LTTNG_CLIENT_METADATA:
		memcpy(&config->cb, lttng_client_callbacks_metadata,
			sizeof(config->cb));
		break;
	case LTTNG_CLIENT_DISCARD:
		memcpy(&config->cb, lttng_client_callbacks_discard,
			sizeof(config->cb));
		break;
	case LTTNG_CLIENT_OVERWRITE:
		memcpy(&config->cb, lttng_client_callbacks_overwrite,
			sizeof(config->cb));
		break;
	default:
		ERR("Unknown client type %d", config->client_type);
		channel_destroy(chan, handle, 1);
		return NULL;
	}
	/* Replace the object table pointer. */
	ret = munmap(handle->table->objects[0].memory_map,
		handle->table->objects[0].memory_map_size);
	if (ret) {
		perror("munmap");
		assert(0);
	}
	handle->table->objects[0].memory_map = (char *) handle->shadow_chan;
	handle->table->objects[0].is_shadow = 1;
	return handle;
}

/* Add stream to channel shm and map its shm into process memory */
int ustctl_add_stream(struct lttng_ust_shm_handle *handle,
		struct lttng_ust_object_data *stream_data)
{
	int ret;

	if (!handle || !stream_data)
		return -EINVAL;

	if (!stream_data->handle)
		return -ENOENT;
	/* map stream */
	ret = channel_handle_add_stream(handle,
		stream_data->shm_fd,
		stream_data->wait_fd,
		stream_data->memory_map_size);
	if (ret) {
		ERR("add stream error\n");
		return ret;
	}
	/*
	 * Set to -1 because the lttng_ust_shm_handle destruction will take care
	 * of closing shm_fd and wait_fd.
	 */
	stream_data->shm_fd = -1;
	stream_data->wait_fd = -1;
	return 0;
}

void ustctl_unmap_channel(struct lttng_ust_shm_handle *handle)
{
	struct channel *chan;

	assert(handle);
	chan = shmp(handle, handle->chan);
	channel_destroy(chan, handle, 1);
}

/*
 * ustctl closes the shm_fd fds after mapping it.
 */
struct lttng_ust_lib_ring_buffer *ustctl_open_stream_read(struct lttng_ust_shm_handle *handle,
	int cpu)
{
	struct channel *chan;
	int *shm_fd, *wait_fd;
	uint64_t *memory_map_size;
	struct lttng_ust_lib_ring_buffer *buf;
	int ret;

	if (!handle)
		return NULL;

	chan = handle->shadow_chan;
	buf = channel_get_ring_buffer(&chan->backend.config,
		chan, cpu, handle, &shm_fd, &wait_fd, &memory_map_size);
	if (!buf)
		return NULL;
	ret = lib_ring_buffer_open_read(buf, handle, 1);
	if (ret)
		return NULL;
	/*
	 * We can close shm_fd early, right after is has been mapped.
	 */
	if (*shm_fd >= 0) {
		ret = close(*shm_fd);
		if (ret) {
			perror("Error closing shm_fd");
		}
		*shm_fd = -1;
	}
	return buf;
}

void ustctl_close_stream_read(struct lttng_ust_shm_handle *handle,
		struct lttng_ust_lib_ring_buffer *buf)
{
	assert(handle && buf);
	lib_ring_buffer_release_read(buf, handle, 1);
}

/* For mmap mode, readable without "get" operation */

void *ustctl_get_mmap_base(struct lttng_ust_shm_handle *handle,
		struct lttng_ust_lib_ring_buffer *buf)
{
	if (!handle || !buf)
		return NULL;
	return shmp(handle, buf->backend.memory_map);
}

/* returns the length to mmap. */
int ustctl_get_mmap_len(struct lttng_ust_shm_handle *handle,
		struct lttng_ust_lib_ring_buffer *buf,
		unsigned long *len)
{
	unsigned long mmap_buf_len;
	struct channel *chan;

	if (!handle || !buf || !len)
		return -EINVAL;

	chan = handle->shadow_chan;
	if (chan->backend.config.output != RING_BUFFER_MMAP)
		return -EINVAL;
	mmap_buf_len = chan->backend.buf_size;
	if (chan->backend.extra_reader_sb)
		mmap_buf_len += chan->backend.subbuf_size;
	if (mmap_buf_len > INT_MAX)
		return -EFBIG;
	*len = mmap_buf_len;
	return 0;
}

/* returns the maximum size for sub-buffers. */
int ustctl_get_max_subbuf_size(struct lttng_ust_shm_handle *handle,
		struct lttng_ust_lib_ring_buffer *buf,
		unsigned long *len)
{
	struct channel *chan;

	if (!handle || !buf || !len)
		return -EINVAL;

	chan = handle->shadow_chan;
	*len = chan->backend.subbuf_size;
	return 0;
}

/*
 * For mmap mode, operate on the current packet (between get/put or
 * get_next/put_next).
 */

/* returns the offset of the subbuffer belonging to the mmap reader. */
int ustctl_get_mmap_read_offset(struct lttng_ust_shm_handle *handle,
		struct lttng_ust_lib_ring_buffer *buf, unsigned long *off)
{
	struct channel *chan;
	unsigned long sb_bindex;

	if (!handle || !buf || !off)
		return -EINVAL;

	chan = handle->shadow_chan;
	if (chan->backend.config.output != RING_BUFFER_MMAP)
		return -EINVAL;
	sb_bindex = subbuffer_id_get_index(&chan->backend.config,
					   buf->backend.buf_rsb.id);
	*off = shmp(handle, shmp_index(handle, buf->backend.array, sb_bindex)->shmp)->mmap_offset;
	return 0;
}

/* returns the size of the current sub-buffer, without padding (for mmap). */
int ustctl_get_subbuf_size(struct lttng_ust_shm_handle *handle,
		struct lttng_ust_lib_ring_buffer *buf, unsigned long *len)
{
	struct channel *chan;

	if (!handle || !buf || !len)
		return -EINVAL;

	chan = handle->shadow_chan;
	*len = lib_ring_buffer_get_read_data_size(&chan->backend.config, buf,
		handle);
	return 0;
}

/* returns the size of the current sub-buffer, without padding (for mmap). */
int ustctl_get_padded_subbuf_size(struct lttng_ust_shm_handle *handle,
		struct lttng_ust_lib_ring_buffer *buf, unsigned long *len)
{
	struct channel *chan;

	if (!handle || !buf || !len)
		return -EINVAL;

	chan = handle->shadow_chan;
	*len = lib_ring_buffer_get_read_data_size(&chan->backend.config, buf,
		handle);
	*len = PAGE_ALIGN(*len);
	return 0;
}

/* Get exclusive read access to the next sub-buffer that can be read. */
int ustctl_get_next_subbuf(struct lttng_ust_shm_handle *handle,
		struct lttng_ust_lib_ring_buffer *buf)
{
	if (!handle || !buf)
		return -EINVAL;

	return lib_ring_buffer_get_next_subbuf(buf, handle);
}


/* Release exclusive sub-buffer access, move consumer forward. */
int ustctl_put_next_subbuf(struct lttng_ust_shm_handle *handle,
		struct lttng_ust_lib_ring_buffer *buf)
{
	if (!handle || !buf)
		return -EINVAL;

	lib_ring_buffer_put_next_subbuf(buf, handle);
	return 0;
}

/* snapshot */

/* Get a snapshot of the current ring buffer producer and consumer positions */
int ustctl_snapshot(struct lttng_ust_shm_handle *handle,
		struct lttng_ust_lib_ring_buffer *buf)
{
	if (!handle || !buf)
		return -EINVAL;

	return lib_ring_buffer_snapshot(buf, &buf->cons_snapshot,
			&buf->prod_snapshot, handle);
}

/* Get the consumer position (iteration start) */
int ustctl_snapshot_get_consumed(struct lttng_ust_shm_handle *handle,
		struct lttng_ust_lib_ring_buffer *buf, unsigned long *pos)
{
	if (!handle || !buf || !pos)
		return -EINVAL;

	*pos = buf->cons_snapshot;
	return 0;
}

/* Get the producer position (iteration end) */
int ustctl_snapshot_get_produced(struct lttng_ust_shm_handle *handle,
		struct lttng_ust_lib_ring_buffer *buf, unsigned long *pos)
{
	if (!handle || !buf || !pos)
		return -EINVAL;

	*pos = buf->prod_snapshot;
	return 0;
}

/* Get exclusive read access to the specified sub-buffer position */
int ustctl_get_subbuf(struct lttng_ust_shm_handle *handle,
		struct lttng_ust_lib_ring_buffer *buf, unsigned long *pos)
{
	if (!handle || !buf || !pos)
		return -EINVAL;

	return lib_ring_buffer_get_subbuf(buf, *pos, handle);
}

/* Release exclusive sub-buffer access */
int ustctl_put_subbuf(struct lttng_ust_shm_handle *handle,
		struct lttng_ust_lib_ring_buffer *buf)
{
	if (!handle || !buf)
		return -EINVAL;

	lib_ring_buffer_put_subbuf(buf, handle);
	return 0;
}

void ustctl_flush_buffer(struct lttng_ust_shm_handle *handle,
		struct lttng_ust_lib_ring_buffer *buf,
		int producer_active)
{
	assert(handle && buf);
	lib_ring_buffer_switch_slow(buf,
		producer_active ? SWITCH_ACTIVE : SWITCH_FLUSH,
		handle);
}
