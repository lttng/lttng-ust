/*
 * Copyright (C) 2011 - Julien Desfossez <julien.desfossez@polymtl.ca>
 * Copyright (C) 2011-2013 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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
#include <byteswap.h>

#include <usterr-signal-safe.h>
#include <ust-comm.h>
#include <helper.h>

#include "../libringbuffer/backend.h"
#include "../libringbuffer/frontend.h"
#include "../liblttng-ust/wait.h"
#include "../liblttng-ust/lttng-rb-clients.h"
#include "../liblttng-ust/clock.h"

/*
 * Number of milliseconds to retry before failing metadata writes on
 * buffer full condition. (10 seconds)
 */
#define LTTNG_METADATA_TIMEOUT_MSEC	10000

/*
 * Channel representation within consumer.
 */
struct ustctl_consumer_channel {
	struct lttng_channel *chan;		/* lttng channel buffers */

	/* initial attributes */
	struct ustctl_consumer_channel_attr attr;
	int wait_fd;				/* monitor close() */
	int wakeup_fd;				/* monitor close() */
};

/*
 * Stream representation within consumer.
 */
struct ustctl_consumer_stream {
	struct lttng_ust_shm_handle *handle;	/* shared-memory handle */
	struct lttng_ust_lib_ring_buffer *buf;
	struct ustctl_consumer_channel *chan;
	int shm_fd, wait_fd, wakeup_fd;
	int cpu;
	uint64_t memory_map_size;
};

extern void lttng_ring_buffer_client_overwrite_init(void);
extern void lttng_ring_buffer_client_overwrite_rt_init(void);
extern void lttng_ring_buffer_client_discard_init(void);
extern void lttng_ring_buffer_client_discard_rt_init(void);
extern void lttng_ring_buffer_metadata_client_init(void);
extern void lttng_ring_buffer_client_overwrite_exit(void);
extern void lttng_ring_buffer_client_overwrite_rt_exit(void);
extern void lttng_ring_buffer_client_discard_exit(void);
extern void lttng_ring_buffer_client_discard_rt_exit(void);
extern void lttng_ring_buffer_metadata_client_exit(void);

volatile enum ust_loglevel ust_loglevel;

int ustctl_release_handle(int sock, int handle)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;

	if (sock < 0 || handle < 0)
		return 0;
	memset(&lum, 0, sizeof(lum));
	lum.handle = handle;
	lum.cmd = LTTNG_UST_RELEASE;
	return ustcomm_send_app_cmd(sock, &lum, &lur);
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

	switch (data->type) {
	case LTTNG_UST_OBJECT_TYPE_CHANNEL:
		if (data->u.channel.wakeup_fd >= 0) {
			ret = close(data->u.channel.wakeup_fd);
			if (ret < 0) {
				ret = -errno;
				return ret;
			}
		}
		free(data->u.channel.data);
		break;
	case LTTNG_UST_OBJECT_TYPE_STREAM:
		if (data->u.stream.shm_fd >= 0) {
			ret = close(data->u.stream.shm_fd);
			if (ret < 0) {
				ret = -errno;
				return ret;
			}
		}
		if (data->u.stream.wakeup_fd >= 0) {
			ret = close(data->u.stream.wakeup_fd);
			if (ret < 0) {
				ret = -errno;
				return ret;
			}
		}
		break;
	case LTTNG_UST_OBJECT_TYPE_EVENT:
	case LTTNG_UST_OBJECT_TYPE_CONTEXT:
		break;
	default:
		assert(0);
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
	return 0;
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

	event_data = zmalloc(sizeof(*event_data));
	if (!event_data)
		return -ENOMEM;
	event_data->type = LTTNG_UST_OBJECT_TYPE_EVENT;
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

int ustctl_add_context(int sock, struct lttng_ust_context_attr *ctx,
		struct lttng_ust_object_data *obj_data,
		struct lttng_ust_object_data **_context_data)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	struct lttng_ust_object_data *context_data = NULL;
	char *buf = NULL;
	size_t len;
	int ret;

	if (!obj_data || !_context_data) {
		ret = -EINVAL;
		goto end;
	}

	context_data = zmalloc(sizeof(*context_data));
	if (!context_data) {
		ret = -ENOMEM;
		goto end;
	}
	context_data->type = LTTNG_UST_OBJECT_TYPE_CONTEXT;
	memset(&lum, 0, sizeof(lum));
	lum.handle = obj_data->handle;
	lum.cmd = LTTNG_UST_CONTEXT;

	lum.u.context.ctx = ctx->ctx;
	switch (ctx->ctx) {
	case LTTNG_UST_CONTEXT_PERF_THREAD_COUNTER:
		lum.u.context.u.perf_counter = ctx->u.perf_counter;
		break;
	case LTTNG_UST_CONTEXT_APP_CONTEXT:
	{
		size_t provider_name_len = strlen(
				ctx->u.app_ctx.provider_name) + 1;
		size_t ctx_name_len = strlen(ctx->u.app_ctx.ctx_name) + 1;

		lum.u.context.u.app_ctx.provider_name_len = provider_name_len;
		lum.u.context.u.app_ctx.ctx_name_len = ctx_name_len;

		len = provider_name_len + ctx_name_len;
		buf = zmalloc(len);
		if (!buf) {
			ret = -ENOMEM;
			goto end;
		}
		memcpy(buf, ctx->u.app_ctx.provider_name,
				provider_name_len);
		memcpy(buf + provider_name_len, ctx->u.app_ctx.ctx_name,
				ctx_name_len);
		break;
	}
	default:
		break;
	}
	ret = ustcomm_send_app_msg(sock, &lum);
	if (ret)
		goto end;
	if (buf) {
		/* send var len ctx_name */
		ret = ustcomm_send_unix_sock(sock, buf, len);
		if (ret < 0) {
			goto end;
		}
		if (ret != len) {
			ret = -EINVAL;
			goto end;
		}
	}
	ret = ustcomm_recv_app_reply(sock, &lur, lum.handle, lum.cmd);
	if (ret < 0) {
		goto end;
	}
	context_data->handle = -1;
	DBG("Context created successfully");
	*_context_data = context_data;
	context_data = NULL;
end:
	free(context_data);
	free(buf);
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
	lum.u.filter.seqnum = bytecode->seqnum;

	ret = ustcomm_send_app_msg(sock, &lum);
	if (ret)
		return ret;
	/* send var len bytecode */
	ret = ustcomm_send_unix_sock(sock, bytecode->data,
				bytecode->len);
	if (ret < 0) {
		return ret;
	}
	if (ret != bytecode->len)
		return -EINVAL;
	return ustcomm_recv_app_reply(sock, &lur, lum.handle, lum.cmd);
}

int ustctl_set_exclusion(int sock, struct lttng_ust_event_exclusion *exclusion,
		struct lttng_ust_object_data *obj_data)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret;

	if (!obj_data) {
		return -EINVAL;
	}

	memset(&lum, 0, sizeof(lum));
	lum.handle = obj_data->handle;
	lum.cmd = LTTNG_UST_EXCLUSION;
	lum.u.exclusion.count = exclusion->count;

	ret = ustcomm_send_app_msg(sock, &lum);
	if (ret) {
		return ret;
	}

	/* send var len exclusion names */
	ret = ustcomm_send_unix_sock(sock,
			exclusion->names,
			exclusion->count * LTTNG_UST_SYM_NAME_LEN);
	if (ret < 0) {
		return ret;
	}
	if (ret != exclusion->count * LTTNG_UST_SYM_NAME_LEN) {
		return -EINVAL;
	}
	return ustcomm_recv_app_reply(sock, &lur, lum.handle, lum.cmd);
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

static
int ustctl_send_channel(int sock,
		enum lttng_ust_chan_type type,
		void *data,
		uint64_t size,
		int wakeup_fd,
		int send_fd_only)
{
	ssize_t len;

	if (!send_fd_only) {
		/* Send mmap size */
		len = ustcomm_send_unix_sock(sock, &size, sizeof(size));
		if (len != sizeof(size)) {
			if (len < 0)
				return len;
			else
				return -EIO;
		}

		/* Send channel type */
		len = ustcomm_send_unix_sock(sock, &type, sizeof(type));
		if (len != sizeof(type)) {
			if (len < 0)
				return len;
			else
				return -EIO;
		}
	}

	/* Send channel data */
	len = ustcomm_send_unix_sock(sock, data, size);
	if (len != size) {
		if (len < 0)
			return len;
		else
			return -EIO;
	}

	/* Send wakeup fd */
	len = ustcomm_send_fds_unix_sock(sock, &wakeup_fd, 1);
	if (len <= 0) {
		if (len < 0)
			return len;
		else
			return -EIO;
	}
	return 0;
}

static
int ustctl_send_stream(int sock,
		uint32_t stream_nr,
		uint64_t memory_map_size,
		int shm_fd, int wakeup_fd,
		int send_fd_only)
{
	ssize_t len;
	int fds[2];

	if (!send_fd_only) {
		if (shm_fd < 0) {
			/* finish iteration */
			uint64_t v = -1;

			len = ustcomm_send_unix_sock(sock, &v, sizeof(v));
			if (len != sizeof(v)) {
				if (len < 0)
					return len;
				else
					return -EIO;
			}
			return 0;
		}

		/* Send mmap size */
		len = ustcomm_send_unix_sock(sock, &memory_map_size,
			sizeof(memory_map_size));
		if (len != sizeof(memory_map_size)) {
			if (len < 0)
				return len;
			else
				return -EIO;
		}

		/* Send stream nr */
		len = ustcomm_send_unix_sock(sock, &stream_nr,
			sizeof(stream_nr));
		if (len != sizeof(stream_nr)) {
			if (len < 0)
				return len;
			else
				return -EIO;
		}
	}

	/* Send shm fd and wakeup fd */
	fds[0] = shm_fd;
	fds[1] = wakeup_fd;
	len = ustcomm_send_fds_unix_sock(sock, fds, 2);
	if (len <= 0) {
		if (len < 0)
			return len;
		else
			return -EIO;
	}
	return 0;
}

int ustctl_recv_channel_from_consumer(int sock,
		struct lttng_ust_object_data **_channel_data)
{
	struct lttng_ust_object_data *channel_data;
	ssize_t len;
	int wakeup_fd;
	int ret;

	channel_data = zmalloc(sizeof(*channel_data));
	if (!channel_data) {
		ret = -ENOMEM;
		goto error_alloc;
	}
	channel_data->type = LTTNG_UST_OBJECT_TYPE_CHANNEL;
	channel_data->handle = -1;

	/* recv mmap size */
	len = ustcomm_recv_unix_sock(sock, &channel_data->size,
			sizeof(channel_data->size));
	if (len != sizeof(channel_data->size)) {
		if (len < 0)
			ret = len;
		else
			ret = -EINVAL;
		goto error;
	}

	/* recv channel type */
	len = ustcomm_recv_unix_sock(sock, &channel_data->u.channel.type,
			sizeof(channel_data->u.channel.type));
	if (len != sizeof(channel_data->u.channel.type)) {
		if (len < 0)
			ret = len;
		else
			ret = -EINVAL;
		goto error;
	}

	/* recv channel data */
	channel_data->u.channel.data = zmalloc(channel_data->size);
	if (!channel_data->u.channel.data) {
		ret = -ENOMEM;
		goto error;
	}
	len = ustcomm_recv_unix_sock(sock, channel_data->u.channel.data,
			channel_data->size);
	if (len != channel_data->size) {
		if (len < 0)
			ret = len;
		else
			ret = -EINVAL;
		goto error_recv_data;
	}
	/* recv wakeup fd */
	len = ustcomm_recv_fds_unix_sock(sock, &wakeup_fd, 1);
	if (len <= 0) {
		if (len < 0) {
			ret = len;
			goto error_recv_data;
		} else {
			ret = -EIO;
			goto error_recv_data;
		}
	}
	channel_data->u.channel.wakeup_fd = wakeup_fd;
	*_channel_data = channel_data;
	return 0;

error_recv_data:
	free(channel_data->u.channel.data);
error:
	free(channel_data);
error_alloc:
	return ret;
}

int ustctl_recv_stream_from_consumer(int sock,
		struct lttng_ust_object_data **_stream_data)
{
	struct lttng_ust_object_data *stream_data;
	ssize_t len;
	int ret;
	int fds[2];

	stream_data = zmalloc(sizeof(*stream_data));
	if (!stream_data) {
		ret = -ENOMEM;
		goto error_alloc;
	}

	stream_data->type = LTTNG_UST_OBJECT_TYPE_STREAM;
	stream_data->handle = -1;

	/* recv mmap size */
	len = ustcomm_recv_unix_sock(sock, &stream_data->size,
			sizeof(stream_data->size));
	if (len != sizeof(stream_data->size)) {
		if (len < 0)
			ret = len;
		else
			ret = -EINVAL;
		goto error;
	}
	if (stream_data->size == -1) {
		ret = -LTTNG_UST_ERR_NOENT;
		goto error;
	}

	/* recv stream nr */
	len = ustcomm_recv_unix_sock(sock, &stream_data->u.stream.stream_nr,
			sizeof(stream_data->u.stream.stream_nr));
	if (len != sizeof(stream_data->u.stream.stream_nr)) {
		if (len < 0)
			ret = len;
		else
			ret = -EINVAL;
		goto error;
	}

	/* recv shm fd and wakeup fd */
	len = ustcomm_recv_fds_unix_sock(sock, fds, 2);
	if (len <= 0) {
		if (len < 0) {
			ret = len;
			goto error;
		} else {
			ret = -EIO;
			goto error;
		}
	}
	stream_data->u.stream.shm_fd = fds[0];
	stream_data->u.stream.wakeup_fd = fds[1];
	*_stream_data = stream_data;
	return 0;

error:
	free(stream_data);
error_alloc:
	return ret;
}

int ustctl_send_channel_to_ust(int sock, int session_handle,
		struct lttng_ust_object_data *channel_data)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret;

	if (!channel_data)
		return -EINVAL;

	memset(&lum, 0, sizeof(lum));
	lum.handle = session_handle;
	lum.cmd = LTTNG_UST_CHANNEL;
	lum.u.channel.len = channel_data->size;
	lum.u.channel.type = channel_data->u.channel.type;
	ret = ustcomm_send_app_msg(sock, &lum);
	if (ret)
		return ret;

	ret = ustctl_send_channel(sock,
			channel_data->u.channel.type,
			channel_data->u.channel.data,
			channel_data->size,
			channel_data->u.channel.wakeup_fd,
			1);
	if (ret)
		return ret;
	ret = ustcomm_recv_app_reply(sock, &lur, lum.handle, lum.cmd);
	if (!ret) {
		channel_data->handle = lur.ret_val;
	}
	return ret;
}

int ustctl_send_stream_to_ust(int sock,
		struct lttng_ust_object_data *channel_data,
		struct lttng_ust_object_data *stream_data)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret;

	memset(&lum, 0, sizeof(lum));
	lum.handle = channel_data->handle;
	lum.cmd = LTTNG_UST_STREAM;
	lum.u.stream.len = stream_data->size;
	lum.u.stream.stream_nr = stream_data->u.stream.stream_nr;
	ret = ustcomm_send_app_msg(sock, &lum);
	if (ret)
		return ret;

	assert(stream_data);
	assert(stream_data->type == LTTNG_UST_OBJECT_TYPE_STREAM);

	ret = ustctl_send_stream(sock,
			stream_data->u.stream.stream_nr,
			stream_data->size,
			stream_data->u.stream.shm_fd,
			stream_data->u.stream.wakeup_fd, 1);
	if (ret)
		return ret;
	return ustcomm_recv_app_reply(sock, &lur, lum.handle, lum.cmd);
}

int ustctl_duplicate_ust_object_data(struct lttng_ust_object_data **dest,
                struct lttng_ust_object_data *src)
{
	struct lttng_ust_object_data *obj;
	int ret;

	if (src->handle != -1) {
		ret = -EINVAL;
		goto error;
	}

	obj = zmalloc(sizeof(*obj));
	if (!obj) {
		ret = -ENOMEM;
		goto error;
	}

	obj->type = src->type;
	obj->handle = src->handle;
	obj->size = src->size;

	switch (obj->type) {
	case LTTNG_UST_OBJECT_TYPE_CHANNEL:
	{
		obj->u.channel.type = src->u.channel.type;
		if (src->u.channel.wakeup_fd >= 0) {
			obj->u.channel.wakeup_fd =
				dup(src->u.channel.wakeup_fd);
			if (obj->u.channel.wakeup_fd < 0) {
				ret = errno;
				goto chan_error_wakeup_fd;
			}
		} else {
			obj->u.channel.wakeup_fd =
				src->u.channel.wakeup_fd;
		}
		obj->u.channel.data = zmalloc(obj->size);
		if (!obj->u.channel.data) {
			ret = -ENOMEM;
			goto chan_error_alloc;
		}
		memcpy(obj->u.channel.data, src->u.channel.data, obj->size);
		break;

	chan_error_alloc:
		if (src->u.channel.wakeup_fd >= 0) {
			int closeret;

			closeret = close(obj->u.channel.wakeup_fd);
			if (closeret) {
				PERROR("close");
			}
		}
	chan_error_wakeup_fd:
		goto error_type;

	}

	case LTTNG_UST_OBJECT_TYPE_STREAM:
	{
		obj->u.stream.stream_nr = src->u.stream.stream_nr;
		if (src->u.stream.wakeup_fd >= 0) {
			obj->u.stream.wakeup_fd =
				dup(src->u.stream.wakeup_fd);
			if (obj->u.stream.wakeup_fd < 0) {
				ret = errno;
				goto stream_error_wakeup_fd;
			}
		} else {
			obj->u.stream.wakeup_fd =
				src->u.stream.wakeup_fd;
		}

		if (src->u.stream.shm_fd >= 0) {
			obj->u.stream.shm_fd =
				dup(src->u.stream.shm_fd);
			if (obj->u.stream.shm_fd < 0) {
				ret = errno;
				goto stream_error_shm_fd;
			}
		} else {
			obj->u.stream.shm_fd =
				src->u.stream.shm_fd;
		}
		break;

	stream_error_shm_fd:
		if (src->u.stream.wakeup_fd >= 0) {
			int closeret;

			closeret = close(obj->u.stream.wakeup_fd);
			if (closeret) {
				PERROR("close");
			}
		}
	stream_error_wakeup_fd:
		goto error_type;
	}

	default:
		ret = -EINVAL;
		goto error_type;
	}

	*dest = obj;
	return 0;

error_type:
	free(obj);
error:
	return ret;
}


/* Buffer operations */

int ustctl_get_nr_stream_per_channel(void)
{
	return num_possible_cpus();
}

struct ustctl_consumer_channel *
	ustctl_create_channel(struct ustctl_consumer_channel_attr *attr,
		const int *stream_fds, int nr_stream_fds)
{
	struct ustctl_consumer_channel *chan;
	const char *transport_name;
	struct lttng_transport *transport;

	switch (attr->type) {
	case LTTNG_UST_CHAN_PER_CPU:
		if (attr->output == LTTNG_UST_MMAP) {
			if (attr->overwrite) {
				if (attr->read_timer_interval == 0) {
					transport_name = "relay-overwrite-mmap";
				} else {
					transport_name = "relay-overwrite-rt-mmap";
				}
			} else {
				if (attr->read_timer_interval == 0) {
					transport_name = "relay-discard-mmap";
				} else {
					transport_name = "relay-discard-rt-mmap";
				}
			}
		} else {
			return NULL;
		}
		break;
	case LTTNG_UST_CHAN_METADATA:
		if (attr->output == LTTNG_UST_MMAP)
			transport_name = "relay-metadata-mmap";
		else
			return NULL;
		break;
	default:
		transport_name = "<unknown>";
		return NULL;
	}

	transport = lttng_transport_find(transport_name);
	if (!transport) {
		DBG("LTTng transport %s not found\n",
			transport_name);
		return NULL;
	}

	chan = zmalloc(sizeof(*chan));
	if (!chan)
		return NULL;

	chan->chan = transport->ops.channel_create(transport_name, NULL,
			attr->subbuf_size, attr->num_subbuf,
			attr->switch_timer_interval,
			attr->read_timer_interval,
			attr->uuid, attr->chan_id,
			stream_fds, nr_stream_fds);
	if (!chan->chan) {
		goto chan_error;
	}
	chan->chan->ops = &transport->ops;
	memcpy(&chan->attr, attr, sizeof(chan->attr));
	chan->wait_fd = ustctl_channel_get_wait_fd(chan);
	chan->wakeup_fd = ustctl_channel_get_wakeup_fd(chan);
	return chan;

chan_error:
	free(chan);
	return NULL;
}

void ustctl_destroy_channel(struct ustctl_consumer_channel *chan)
{
	(void) ustctl_channel_close_wait_fd(chan);
	(void) ustctl_channel_close_wakeup_fd(chan);
	chan->chan->ops->channel_destroy(chan->chan);
	free(chan);
}

int ustctl_send_channel_to_sessiond(int sock,
		struct ustctl_consumer_channel *channel)
{
	struct shm_object_table *table;

	table = channel->chan->handle->table;
	if (table->size <= 0)
		return -EINVAL;
	return ustctl_send_channel(sock,
			channel->attr.type,
			table->objects[0].memory_map,
			table->objects[0].memory_map_size,
			channel->wakeup_fd,
			0);
}

int ustctl_send_stream_to_sessiond(int sock,
		struct ustctl_consumer_stream *stream)
{
	if (!stream)
		return ustctl_send_stream(sock, -1U, -1U, -1, -1, 0);

	return ustctl_send_stream(sock,
			stream->cpu,
			stream->memory_map_size,
			stream->shm_fd, stream->wakeup_fd,
			0);
}

int ustctl_write_metadata_to_channel(
		struct ustctl_consumer_channel *channel,
		const char *metadata_str,	/* NOT null-terminated */
		size_t len)			/* metadata length */
{
	struct lttng_ust_lib_ring_buffer_ctx ctx;
	struct lttng_channel *chan = channel->chan;
	const char *str = metadata_str;
	int ret = 0, waitret;
	size_t reserve_len, pos;

	for (pos = 0; pos < len; pos += reserve_len) {
		reserve_len = min_t(size_t,
				chan->ops->packet_avail_size(chan->chan, chan->handle),
				len - pos);
		lib_ring_buffer_ctx_init(&ctx, chan->chan, NULL, reserve_len,
					 sizeof(char), -1, chan->handle, NULL);
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
	return ret;
}

/*
 * Write at most one packet in the channel.
 * Returns the number of bytes written on success, < 0 on error.
 */
ssize_t ustctl_write_one_packet_to_channel(
		struct ustctl_consumer_channel *channel,
		const char *metadata_str,	/* NOT null-terminated */
		size_t len)			/* metadata length */
{
	struct lttng_ust_lib_ring_buffer_ctx ctx;
	struct lttng_channel *chan = channel->chan;
	const char *str = metadata_str;
	ssize_t reserve_len;
	int ret;

	reserve_len = min_t(ssize_t,
			chan->ops->packet_avail_size(chan->chan, chan->handle),
			len);
	lib_ring_buffer_ctx_init(&ctx, chan->chan, NULL, reserve_len,
			sizeof(char), -1, chan->handle, NULL);
	ret = chan->ops->event_reserve(&ctx, 0);
	if (ret != 0) {
		DBG("LTTng: event reservation failed");
		assert(ret < 0);
		reserve_len = ret;
		goto end;
	}
	chan->ops->event_write(&ctx, str, reserve_len);
	chan->ops->event_commit(&ctx);

end:
	return reserve_len;
}

int ustctl_channel_close_wait_fd(struct ustctl_consumer_channel *consumer_chan)
{
	struct channel *chan;
	int ret;

	chan = consumer_chan->chan->chan;
	ret = ring_buffer_channel_close_wait_fd(&chan->backend.config,
			chan, chan->handle);
	if (!ret)
		consumer_chan->wait_fd = -1;
	return ret;
}

int ustctl_channel_close_wakeup_fd(struct ustctl_consumer_channel *consumer_chan)
{
	struct channel *chan;
	int ret;

	chan = consumer_chan->chan->chan;
	ret = ring_buffer_channel_close_wakeup_fd(&chan->backend.config,
			chan, chan->handle);
	if (!ret)
		consumer_chan->wakeup_fd = -1;
	return ret;
}

int ustctl_stream_close_wait_fd(struct ustctl_consumer_stream *stream)
{
	struct channel *chan;

	chan = stream->chan->chan->chan;
	return ring_buffer_stream_close_wait_fd(&chan->backend.config,
			chan, stream->handle, stream->cpu);
}

int ustctl_stream_close_wakeup_fd(struct ustctl_consumer_stream *stream)
{
	struct channel *chan;

	chan = stream->chan->chan->chan;
	return ring_buffer_stream_close_wakeup_fd(&chan->backend.config,
			chan, stream->handle, stream->cpu);
}

struct ustctl_consumer_stream *
	ustctl_create_stream(struct ustctl_consumer_channel *channel,
			int cpu)
{
	struct ustctl_consumer_stream *stream;
	struct lttng_ust_shm_handle *handle;
	struct channel *chan;
	int shm_fd, wait_fd, wakeup_fd;
	uint64_t memory_map_size;
	struct lttng_ust_lib_ring_buffer *buf;
	int ret;

	if (!channel)
		return NULL;
	handle = channel->chan->handle;
	if (!handle)
		return NULL;

	chan = channel->chan->chan;
	buf = channel_get_ring_buffer(&chan->backend.config,
		chan, cpu, handle, &shm_fd, &wait_fd,
		&wakeup_fd, &memory_map_size);
	if (!buf)
		return NULL;
	ret = lib_ring_buffer_open_read(buf, handle);
	if (ret)
		return NULL;

	stream = zmalloc(sizeof(*stream));
	if (!stream)
		goto alloc_error;
	stream->handle = handle;
	stream->buf = buf;
	stream->chan = channel;
	stream->shm_fd = shm_fd;
	stream->wait_fd = wait_fd;
	stream->wakeup_fd = wakeup_fd;
	stream->memory_map_size = memory_map_size;
	stream->cpu = cpu;
	return stream;

alloc_error:
	return NULL;
}

void ustctl_destroy_stream(struct ustctl_consumer_stream *stream)
{
	struct lttng_ust_lib_ring_buffer *buf;
	struct ustctl_consumer_channel *consumer_chan;

	assert(stream);
	buf = stream->buf;
	consumer_chan = stream->chan;
	(void) ustctl_stream_close_wait_fd(stream);
	(void) ustctl_stream_close_wakeup_fd(stream);
	lib_ring_buffer_release_read(buf, consumer_chan->chan->handle);
	free(stream);
}

int ustctl_channel_get_wait_fd(struct ustctl_consumer_channel *chan)
{
	if (!chan)
		return -EINVAL;
	return shm_get_wait_fd(chan->chan->handle,
		&chan->chan->handle->chan._ref);
}

int ustctl_channel_get_wakeup_fd(struct ustctl_consumer_channel *chan)
{
	if (!chan)
		return -EINVAL;
	return shm_get_wakeup_fd(chan->chan->handle,
		&chan->chan->handle->chan._ref);
}

int ustctl_stream_get_wait_fd(struct ustctl_consumer_stream *stream)
{
	struct lttng_ust_lib_ring_buffer *buf;
	struct ustctl_consumer_channel *consumer_chan;

	if (!stream)
		return -EINVAL;
	buf = stream->buf;
	consumer_chan = stream->chan;
	return shm_get_wait_fd(consumer_chan->chan->handle, &buf->self._ref);
}

int ustctl_stream_get_wakeup_fd(struct ustctl_consumer_stream *stream)
{
	struct lttng_ust_lib_ring_buffer *buf;
	struct ustctl_consumer_channel *consumer_chan;

	if (!stream)
		return -EINVAL;
	buf = stream->buf;
	consumer_chan = stream->chan;
	return shm_get_wakeup_fd(consumer_chan->chan->handle, &buf->self._ref);
}

/* For mmap mode, readable without "get" operation */

void *ustctl_get_mmap_base(struct ustctl_consumer_stream *stream)
{
	struct lttng_ust_lib_ring_buffer *buf;
	struct ustctl_consumer_channel *consumer_chan;

	if (!stream)
		return NULL;
	buf = stream->buf;
	consumer_chan = stream->chan;
	return shmp(consumer_chan->chan->handle, buf->backend.memory_map);
}

/* returns the length to mmap. */
int ustctl_get_mmap_len(struct ustctl_consumer_stream *stream,
		unsigned long *len)
{
	struct ustctl_consumer_channel *consumer_chan;
	unsigned long mmap_buf_len;
	struct channel *chan;

	if (!stream)
		return -EINVAL;
	consumer_chan = stream->chan;
	chan = consumer_chan->chan->chan;
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
int ustctl_get_max_subbuf_size(struct ustctl_consumer_stream *stream,
		unsigned long *len)
{
	struct ustctl_consumer_channel *consumer_chan;
	struct channel *chan;

	if (!stream)
		return -EINVAL;
	consumer_chan = stream->chan;
	chan = consumer_chan->chan->chan;
	*len = chan->backend.subbuf_size;
	return 0;
}

/*
 * For mmap mode, operate on the current packet (between get/put or
 * get_next/put_next).
 */

/* returns the offset of the subbuffer belonging to the mmap reader. */
int ustctl_get_mmap_read_offset(struct ustctl_consumer_stream *stream,
		unsigned long *off)
{
	struct channel *chan;
	unsigned long sb_bindex;
	struct lttng_ust_lib_ring_buffer *buf;
	struct ustctl_consumer_channel *consumer_chan;
	struct lttng_ust_lib_ring_buffer_backend_pages_shmp *barray_idx;
	struct lttng_ust_lib_ring_buffer_backend_pages *pages;

	if (!stream)
		return -EINVAL;
	buf = stream->buf;
	consumer_chan = stream->chan;
	chan = consumer_chan->chan->chan;
	if (chan->backend.config.output != RING_BUFFER_MMAP)
		return -EINVAL;
	sb_bindex = subbuffer_id_get_index(&chan->backend.config,
					buf->backend.buf_rsb.id);
	barray_idx = shmp_index(consumer_chan->chan->handle, buf->backend.array,
			sb_bindex);
	if (!barray_idx)
		return -EINVAL;
	pages = shmp(consumer_chan->chan->handle, barray_idx->shmp);
	if (!pages)
		return -EINVAL;
	*off = pages->mmap_offset;
	return 0;
}

/* returns the size of the current sub-buffer, without padding (for mmap). */
int ustctl_get_subbuf_size(struct ustctl_consumer_stream *stream,
		unsigned long *len)
{
	struct ustctl_consumer_channel *consumer_chan;
	struct channel *chan;
	struct lttng_ust_lib_ring_buffer *buf;

	if (!stream)
		return -EINVAL;

	buf = stream->buf;
	consumer_chan = stream->chan;
	chan = consumer_chan->chan->chan;
	*len = lib_ring_buffer_get_read_data_size(&chan->backend.config, buf,
		consumer_chan->chan->handle);
	return 0;
}

/* returns the size of the current sub-buffer, without padding (for mmap). */
int ustctl_get_padded_subbuf_size(struct ustctl_consumer_stream *stream,
		unsigned long *len)
{
	struct ustctl_consumer_channel *consumer_chan;
	struct channel *chan;
	struct lttng_ust_lib_ring_buffer *buf;

	if (!stream)
		return -EINVAL;
	buf = stream->buf;
	consumer_chan = stream->chan;
	chan = consumer_chan->chan->chan;
	*len = lib_ring_buffer_get_read_data_size(&chan->backend.config, buf,
		consumer_chan->chan->handle);
	*len = PAGE_ALIGN(*len);
	return 0;
}

/* Get exclusive read access to the next sub-buffer that can be read. */
int ustctl_get_next_subbuf(struct ustctl_consumer_stream *stream)
{
	struct lttng_ust_lib_ring_buffer *buf;
	struct ustctl_consumer_channel *consumer_chan;

	if (!stream)
		return -EINVAL;
	buf = stream->buf;
	consumer_chan = stream->chan;
	return lib_ring_buffer_get_next_subbuf(buf,
			consumer_chan->chan->handle);
}


/* Release exclusive sub-buffer access, move consumer forward. */
int ustctl_put_next_subbuf(struct ustctl_consumer_stream *stream)
{
	struct lttng_ust_lib_ring_buffer *buf;
	struct ustctl_consumer_channel *consumer_chan;

	if (!stream)
		return -EINVAL;
	buf = stream->buf;
	consumer_chan = stream->chan;
	lib_ring_buffer_put_next_subbuf(buf, consumer_chan->chan->handle);
	return 0;
}

/* snapshot */

/* Get a snapshot of the current ring buffer producer and consumer positions */
int ustctl_snapshot(struct ustctl_consumer_stream *stream)
{
	struct lttng_ust_lib_ring_buffer *buf;
	struct ustctl_consumer_channel *consumer_chan;

	if (!stream)
		return -EINVAL;
	buf = stream->buf;
	consumer_chan = stream->chan;
	return lib_ring_buffer_snapshot(buf, &buf->cons_snapshot,
			&buf->prod_snapshot, consumer_chan->chan->handle);
}

/* Get the consumer position (iteration start) */
int ustctl_snapshot_get_consumed(struct ustctl_consumer_stream *stream,
		unsigned long *pos)
{
	struct lttng_ust_lib_ring_buffer *buf;

	if (!stream)
		return -EINVAL;
	buf = stream->buf;
	*pos = buf->cons_snapshot;
	return 0;
}

/* Get the producer position (iteration end) */
int ustctl_snapshot_get_produced(struct ustctl_consumer_stream *stream,
		unsigned long *pos)
{
	struct lttng_ust_lib_ring_buffer *buf;

	if (!stream)
		return -EINVAL;
	buf = stream->buf;
	*pos = buf->prod_snapshot;
	return 0;
}

/* Get exclusive read access to the specified sub-buffer position */
int ustctl_get_subbuf(struct ustctl_consumer_stream *stream,
		unsigned long *pos)
{
	struct lttng_ust_lib_ring_buffer *buf;
	struct ustctl_consumer_channel *consumer_chan;

	if (!stream)
		return -EINVAL;
	buf = stream->buf;
	consumer_chan = stream->chan;
	return lib_ring_buffer_get_subbuf(buf, *pos,
			consumer_chan->chan->handle);
}

/* Release exclusive sub-buffer access */
int ustctl_put_subbuf(struct ustctl_consumer_stream *stream)
{
	struct lttng_ust_lib_ring_buffer *buf;
	struct ustctl_consumer_channel *consumer_chan;

	if (!stream)
		return -EINVAL;
	buf = stream->buf;
	consumer_chan = stream->chan;
	lib_ring_buffer_put_subbuf(buf, consumer_chan->chan->handle);
	return 0;
}

void ustctl_flush_buffer(struct ustctl_consumer_stream *stream,
		int producer_active)
{
	struct lttng_ust_lib_ring_buffer *buf;
	struct ustctl_consumer_channel *consumer_chan;

	assert(stream);
	buf = stream->buf;
	consumer_chan = stream->chan;
	lib_ring_buffer_switch_slow(buf,
		producer_active ? SWITCH_ACTIVE : SWITCH_FLUSH,
		consumer_chan->chan->handle);
}

static
struct lttng_ust_client_lib_ring_buffer_client_cb *get_client_cb(
		struct lttng_ust_lib_ring_buffer *buf,
		struct lttng_ust_shm_handle *handle)
{
	struct channel *chan;
	const struct lttng_ust_lib_ring_buffer_config *config;
	struct lttng_ust_client_lib_ring_buffer_client_cb *client_cb;

	chan = shmp(handle, buf->backend.chan);
	if (!chan)
		return NULL;
	config = &chan->backend.config;
	if (!config->cb_ptr)
		return NULL;
	client_cb = caa_container_of(config->cb_ptr,
			struct lttng_ust_client_lib_ring_buffer_client_cb,
			parent);
	return client_cb;
}

int ustctl_get_timestamp_begin(struct ustctl_consumer_stream *stream,
		uint64_t *timestamp_begin)
{
	struct lttng_ust_client_lib_ring_buffer_client_cb *client_cb;
	struct lttng_ust_lib_ring_buffer *buf;
	struct lttng_ust_shm_handle *handle;

	if (!stream || !timestamp_begin)
		return -EINVAL;
	buf = stream->buf;
	handle = stream->chan->chan->handle;
	client_cb = get_client_cb(buf, handle);
	if (!client_cb)
		return -ENOSYS;
	return client_cb->timestamp_begin(buf, handle, timestamp_begin);
}

int ustctl_get_timestamp_end(struct ustctl_consumer_stream *stream,
	uint64_t *timestamp_end)
{
	struct lttng_ust_client_lib_ring_buffer_client_cb *client_cb;
	struct lttng_ust_lib_ring_buffer *buf;
	struct lttng_ust_shm_handle *handle;

	if (!stream || !timestamp_end)
		return -EINVAL;
	buf = stream->buf;
	handle = stream->chan->chan->handle;
	client_cb = get_client_cb(buf, handle);
	if (!client_cb)
		return -ENOSYS;
	return client_cb->timestamp_end(buf, handle, timestamp_end);
}

int ustctl_get_events_discarded(struct ustctl_consumer_stream *stream,
	uint64_t *events_discarded)
{
	struct lttng_ust_client_lib_ring_buffer_client_cb *client_cb;
	struct lttng_ust_lib_ring_buffer *buf;
	struct lttng_ust_shm_handle *handle;

	if (!stream || !events_discarded)
		return -EINVAL;
	buf = stream->buf;
	handle = stream->chan->chan->handle;
	client_cb = get_client_cb(buf, handle);
	if (!client_cb)
		return -ENOSYS;
	return client_cb->events_discarded(buf, handle, events_discarded);
}

int ustctl_get_content_size(struct ustctl_consumer_stream *stream,
	uint64_t *content_size)
{
	struct lttng_ust_client_lib_ring_buffer_client_cb *client_cb;
	struct lttng_ust_lib_ring_buffer *buf;
	struct lttng_ust_shm_handle *handle;

	if (!stream || !content_size)
		return -EINVAL;
	buf = stream->buf;
	handle = stream->chan->chan->handle;
	client_cb = get_client_cb(buf, handle);
	if (!client_cb)
		return -ENOSYS;
	return client_cb->content_size(buf, handle, content_size);
}

int ustctl_get_packet_size(struct ustctl_consumer_stream *stream,
	uint64_t *packet_size)
{
	struct lttng_ust_client_lib_ring_buffer_client_cb *client_cb;
	struct lttng_ust_lib_ring_buffer *buf;
	struct lttng_ust_shm_handle *handle;

	if (!stream || !packet_size)
		return -EINVAL;
	buf = stream->buf;
	handle = stream->chan->chan->handle;
	client_cb = get_client_cb(buf, handle);
	if (!client_cb)
		return -ENOSYS;
	return client_cb->packet_size(buf, handle, packet_size);
}

int ustctl_get_stream_id(struct ustctl_consumer_stream *stream,
		uint64_t *stream_id)
{
	struct lttng_ust_client_lib_ring_buffer_client_cb *client_cb;
	struct lttng_ust_lib_ring_buffer *buf;
	struct lttng_ust_shm_handle *handle;

	if (!stream || !stream_id)
		return -EINVAL;
	buf = stream->buf;
	handle = stream->chan->chan->handle;
	client_cb = get_client_cb(buf, handle);
	if (!client_cb)
		return -ENOSYS;
	return client_cb->stream_id(buf, handle, stream_id);
}

int ustctl_get_current_timestamp(struct ustctl_consumer_stream *stream,
		uint64_t *ts)
{
	struct lttng_ust_client_lib_ring_buffer_client_cb *client_cb;
	struct lttng_ust_lib_ring_buffer *buf;
	struct lttng_ust_shm_handle *handle;

	if (!stream || !ts)
		return -EINVAL;
	buf = stream->buf;
	handle = stream->chan->chan->handle;
	client_cb = get_client_cb(buf, handle);
	if (!client_cb || !client_cb->current_timestamp)
		return -ENOSYS;
	return client_cb->current_timestamp(buf, handle, ts);
}

int ustctl_get_sequence_number(struct ustctl_consumer_stream *stream,
		uint64_t *seq)
{
	struct lttng_ust_client_lib_ring_buffer_client_cb *client_cb;
	struct lttng_ust_lib_ring_buffer *buf;
	struct lttng_ust_shm_handle *handle;

	if (!stream || !seq)
		return -EINVAL;
	buf = stream->buf;
	handle = stream->chan->chan->handle;
	client_cb = get_client_cb(buf, handle);
	if (!client_cb || !client_cb->sequence_number)
		return -ENOSYS;
	return client_cb->sequence_number(buf, handle, seq);
}

#if defined(__x86_64__) || defined(__i386__)

int ustctl_has_perf_counters(void)
{
	return 1;
}

#else

int ustctl_has_perf_counters(void)
{
	return 0;
}

#endif

/*
 * Returns 0 on success, negative error value on error.
 */
int ustctl_recv_reg_msg(int sock,
	enum ustctl_socket_type *type,
	uint32_t *major,
	uint32_t *minor,
	uint32_t *pid,
	uint32_t *ppid,
	uint32_t *uid,
	uint32_t *gid,
	uint32_t *bits_per_long,
	uint32_t *uint8_t_alignment,
	uint32_t *uint16_t_alignment,
	uint32_t *uint32_t_alignment,
	uint32_t *uint64_t_alignment,
	uint32_t *long_alignment,
	int *byte_order,
	char *name)
{
	ssize_t len;
	struct ustctl_reg_msg reg_msg;

	len = ustcomm_recv_unix_sock(sock, &reg_msg, sizeof(reg_msg));
	if (len > 0 && len != sizeof(reg_msg))
		return -EIO;
	if (len == 0)
		return -EPIPE;
	if (len < 0)
		return len;

	if (reg_msg.magic == LTTNG_UST_COMM_MAGIC) {
		*byte_order = BYTE_ORDER == BIG_ENDIAN ?
				BIG_ENDIAN : LITTLE_ENDIAN;
	} else if (reg_msg.magic == bswap_32(LTTNG_UST_COMM_MAGIC)) {
		*byte_order = BYTE_ORDER == BIG_ENDIAN ?
				LITTLE_ENDIAN : BIG_ENDIAN;
	} else {
		return -LTTNG_UST_ERR_INVAL_MAGIC;
	}
	switch (reg_msg.socket_type) {
	case 0:	*type = USTCTL_SOCKET_CMD;
		break;
	case 1:	*type = USTCTL_SOCKET_NOTIFY;
		break;
	default:
		return -LTTNG_UST_ERR_INVAL_SOCKET_TYPE;
	}
	*major = reg_msg.major;
	*minor = reg_msg.minor;
	*pid = reg_msg.pid;
	*ppid = reg_msg.ppid;
	*uid = reg_msg.uid;
	*gid = reg_msg.gid;
	*bits_per_long = reg_msg.bits_per_long;
	*uint8_t_alignment = reg_msg.uint8_t_alignment;
	*uint16_t_alignment = reg_msg.uint16_t_alignment;
	*uint32_t_alignment = reg_msg.uint32_t_alignment;
	*uint64_t_alignment = reg_msg.uint64_t_alignment;
	*long_alignment = reg_msg.long_alignment;
	memcpy(name, reg_msg.name, LTTNG_UST_ABI_PROCNAME_LEN);
	if (reg_msg.major != LTTNG_UST_ABI_MAJOR_VERSION) {
		return -LTTNG_UST_ERR_UNSUP_MAJOR;
	}

	return 0;
}

int ustctl_recv_notify(int sock, enum ustctl_notify_cmd *notify_cmd)
{
	struct ustcomm_notify_hdr header;
	ssize_t len;

	len = ustcomm_recv_unix_sock(sock, &header, sizeof(header));
	if (len > 0 && len != sizeof(header))
		return -EIO;
	if (len == 0)
		return -EPIPE;
	if (len < 0)
		return len;
	switch (header.notify_cmd) {
	case 0:
		*notify_cmd = USTCTL_NOTIFY_CMD_EVENT;
		break;
	case 1:
		*notify_cmd = USTCTL_NOTIFY_CMD_CHANNEL;
		break;
	case 2:
		*notify_cmd = USTCTL_NOTIFY_CMD_ENUM;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

/*
 * Returns 0 on success, negative error value on error.
 */
int ustctl_recv_register_event(int sock,
	int *session_objd,
	int *channel_objd,
	char *event_name,
	int *loglevel,
	char **signature,
	size_t *nr_fields,
	struct ustctl_field **fields,
	char **model_emf_uri)
{
	ssize_t len;
	struct ustcomm_notify_event_msg msg;
	size_t signature_len, fields_len, model_emf_uri_len;
	char *a_sign = NULL, *a_model_emf_uri = NULL;
	struct ustctl_field *a_fields = NULL;

	len = ustcomm_recv_unix_sock(sock, &msg, sizeof(msg));
	if (len > 0 && len != sizeof(msg))
		return -EIO;
	if (len == 0)
		return -EPIPE;
	if (len < 0)
		return len;

	*session_objd = msg.session_objd;
	*channel_objd = msg.channel_objd;
	strncpy(event_name, msg.event_name, LTTNG_UST_SYM_NAME_LEN);
	event_name[LTTNG_UST_SYM_NAME_LEN - 1] = '\0';
	*loglevel = msg.loglevel;
	signature_len = msg.signature_len;
	fields_len = msg.fields_len;

	if (fields_len % sizeof(*a_fields) != 0) {
		return -EINVAL;
	}

	model_emf_uri_len = msg.model_emf_uri_len;

	/* recv signature. contains at least \0. */
	a_sign = zmalloc(signature_len);
	if (!a_sign)
		return -ENOMEM;
	len = ustcomm_recv_unix_sock(sock, a_sign, signature_len);
	if (len > 0 && len != signature_len) {
		len = -EIO;
		goto signature_error;
	}
	if (len == 0) {
		len = -EPIPE;
		goto signature_error;
	}
	if (len < 0) {
		goto signature_error;
	}
	/* Enforce end of string */
	a_sign[signature_len - 1] = '\0';

	/* recv fields */
	if (fields_len) {
		a_fields = zmalloc(fields_len);
		if (!a_fields) {
			len = -ENOMEM;
			goto signature_error;
		}
		len = ustcomm_recv_unix_sock(sock, a_fields, fields_len);
		if (len > 0 && len != fields_len) {
			len = -EIO;
			goto fields_error;
		}
		if (len == 0) {
			len = -EPIPE;
			goto fields_error;
		}
		if (len < 0) {
			goto fields_error;
		}
	}

	if (model_emf_uri_len) {
		/* recv model_emf_uri_len */
		a_model_emf_uri = zmalloc(model_emf_uri_len);
		if (!a_model_emf_uri) {
			len = -ENOMEM;
			goto fields_error;
		}
		len = ustcomm_recv_unix_sock(sock, a_model_emf_uri,
				model_emf_uri_len);
		if (len > 0 && len != model_emf_uri_len) {
			len = -EIO;
			goto model_error;
		}
		if (len == 0) {
			len = -EPIPE;
			goto model_error;
		}
		if (len < 0) {
			goto model_error;
		}
		/* Enforce end of string */
		a_model_emf_uri[model_emf_uri_len - 1] = '\0';
	}

	*signature = a_sign;
	*nr_fields = fields_len / sizeof(*a_fields);
	*fields = a_fields;
	*model_emf_uri = a_model_emf_uri;

	return 0;

model_error:
	free(a_model_emf_uri);
fields_error:
	free(a_fields);
signature_error:
	free(a_sign);
	return len;
}

/*
 * Returns 0 on success, negative error value on error.
 */
int ustctl_reply_register_event(int sock,
	uint32_t id,
	int ret_code)
{
	ssize_t len;
	struct {
		struct ustcomm_notify_hdr header;
		struct ustcomm_notify_event_reply r;
	} reply;

	memset(&reply, 0, sizeof(reply));
	reply.header.notify_cmd = USTCTL_NOTIFY_CMD_EVENT;
	reply.r.ret_code = ret_code;
	reply.r.event_id = id;
	len = ustcomm_send_unix_sock(sock, &reply, sizeof(reply));
	if (len > 0 && len != sizeof(reply))
		return -EIO;
	if (len < 0)
		return len;
	return 0;
}

/*
 * Returns 0 on success, negative UST or system error value on error.
 */
int ustctl_recv_register_enum(int sock,
	int *session_objd,
	char *enum_name,
	struct ustctl_enum_entry **entries,
	size_t *nr_entries)
{
	ssize_t len;
	struct ustcomm_notify_enum_msg msg;
	size_t entries_len;
	struct ustctl_enum_entry *a_entries = NULL;

	len = ustcomm_recv_unix_sock(sock, &msg, sizeof(msg));
	if (len > 0 && len != sizeof(msg))
		return -EIO;
	if (len == 0)
		return -EPIPE;
	if (len < 0)
		return len;

	*session_objd = msg.session_objd;
	strncpy(enum_name, msg.enum_name, LTTNG_UST_SYM_NAME_LEN);
	enum_name[LTTNG_UST_SYM_NAME_LEN - 1] = '\0';
	entries_len = msg.entries_len;

	if (entries_len % sizeof(*a_entries) != 0) {
		return -EINVAL;
	}

	/* recv entries */
	if (entries_len) {
		a_entries = zmalloc(entries_len);
		if (!a_entries)
			return -ENOMEM;
		len = ustcomm_recv_unix_sock(sock, a_entries, entries_len);
		if (len > 0 && len != entries_len) {
			len = -EIO;
			goto entries_error;
		}
		if (len == 0) {
			len = -EPIPE;
			goto entries_error;
		}
		if (len < 0) {
			goto entries_error;
		}
	}
	*nr_entries = entries_len / sizeof(*a_entries);
	*entries = a_entries;

	return 0;

entries_error:
	free(a_entries);
	return len;
}

/*
 * Returns 0 on success, negative error value on error.
 */
int ustctl_reply_register_enum(int sock,
	uint64_t id,
	int ret_code)
{
	ssize_t len;
	struct {
		struct ustcomm_notify_hdr header;
		struct ustcomm_notify_enum_reply r;
	} reply;

	memset(&reply, 0, sizeof(reply));
	reply.header.notify_cmd = USTCTL_NOTIFY_CMD_ENUM;
	reply.r.ret_code = ret_code;
	reply.r.enum_id = id;
	len = ustcomm_send_unix_sock(sock, &reply, sizeof(reply));
	if (len > 0 && len != sizeof(reply))
		return -EIO;
	if (len < 0)
		return len;
	return 0;
}

/*
 * Returns 0 on success, negative UST or system error value on error.
 */
int ustctl_recv_register_channel(int sock,
	int *session_objd,		/* session descriptor (output) */
	int *channel_objd,		/* channel descriptor (output) */
	size_t *nr_fields,
	struct ustctl_field **fields)
{
	ssize_t len;
	struct ustcomm_notify_channel_msg msg;
	size_t fields_len;
	struct ustctl_field *a_fields;

	len = ustcomm_recv_unix_sock(sock, &msg, sizeof(msg));
	if (len > 0 && len != sizeof(msg))
		return -EIO;
	if (len == 0)
		return -EPIPE;
	if (len < 0)
		return len;

	*session_objd = msg.session_objd;
	*channel_objd = msg.channel_objd;
	fields_len = msg.ctx_fields_len;

	if (fields_len % sizeof(*a_fields) != 0) {
		return -EINVAL;
	}

	/* recv fields */
	if (fields_len) {
		a_fields = zmalloc(fields_len);
		if (!a_fields) {
			len = -ENOMEM;
			goto alloc_error;
		}
		len = ustcomm_recv_unix_sock(sock, a_fields, fields_len);
		if (len > 0 && len != fields_len) {
			len = -EIO;
			goto fields_error;
		}
		if (len == 0) {
			len = -EPIPE;
			goto fields_error;
		}
		if (len < 0) {
			goto fields_error;
		}
		*fields = a_fields;
	} else {
		*fields = NULL;
	}
	*nr_fields = fields_len / sizeof(*a_fields);
	return 0;

fields_error:
	free(a_fields);
alloc_error:
	return len;
}

/*
 * Returns 0 on success, negative error value on error.
 */
int ustctl_reply_register_channel(int sock,
	uint32_t chan_id,
	enum ustctl_channel_header header_type,
	int ret_code)
{
	ssize_t len;
	struct {
		struct ustcomm_notify_hdr header;
		struct ustcomm_notify_channel_reply r;
	} reply;

	memset(&reply, 0, sizeof(reply));
	reply.header.notify_cmd = USTCTL_NOTIFY_CMD_CHANNEL;
	reply.r.ret_code = ret_code;
	reply.r.chan_id = chan_id;
	switch (header_type) {
	case USTCTL_CHANNEL_HEADER_COMPACT:
		reply.r.header_type = 1;
		break;
	case USTCTL_CHANNEL_HEADER_LARGE:
		reply.r.header_type = 2;
		break;
	default:
		reply.r.header_type = 0;
		break;
	}
	len = ustcomm_send_unix_sock(sock, &reply, sizeof(reply));
	if (len > 0 && len != sizeof(reply))
		return -EIO;
	if (len < 0)
		return len;
	return 0;
}

static __attribute__((constructor))
void ustctl_init(void)
{
	init_usterr();
	lttng_ust_clock_init();
	lttng_ring_buffer_metadata_client_init();
	lttng_ring_buffer_client_overwrite_init();
	lttng_ring_buffer_client_overwrite_rt_init();
	lttng_ring_buffer_client_discard_init();
	lttng_ring_buffer_client_discard_rt_init();
	lib_ringbuffer_signal_init();
}

static __attribute__((destructor))
void ustctl_exit(void)
{
	lttng_ring_buffer_client_discard_rt_exit();
	lttng_ring_buffer_client_discard_exit();
	lttng_ring_buffer_client_overwrite_rt_exit();
	lttng_ring_buffer_client_overwrite_exit();
	lttng_ring_buffer_metadata_client_exit();
}
