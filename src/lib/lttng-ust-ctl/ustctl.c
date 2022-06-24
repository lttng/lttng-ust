/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2011 EfficiOS Inc.
 * Copyright (C) 2011-2013 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <lttng/ust-config.h>
#include <lttng/ust-ctl.h>
#include <lttng/ust-abi.h>
#include <lttng/ust-endian.h>
#include <lttng/ust-common.h>
#include <lttng/ust-sigbus.h>
#include <urcu/rculist.h>

#include "common/logging.h"
#include "common/ustcomm.h"
#include "common/macros.h"
#include "common/align.h"

#include "common/ringbuffer/backend.h"
#include "common/ringbuffer/frontend.h"
#include "common/events.h"
#include "common/wait.h"
#include "common/ringbuffer-clients/clients.h"
#include "common/getenv.h"
#include "common/tracer.h"
#include "common/counter-clients/clients.h"

#include "common/smp.h"
#include "common/counter/counter.h"

/*
 * Number of milliseconds to retry before failing metadata writes on
 * buffer full condition. (10 seconds)
 */
#define LTTNG_METADATA_TIMEOUT_MSEC	10000

/*
 * Channel representation within consumer.
 */
struct lttng_ust_ctl_consumer_channel {
	struct lttng_ust_channel_buffer *chan;	/* lttng channel buffers */

	/* initial attributes */
	struct lttng_ust_ctl_consumer_channel_attr attr;
	int wait_fd;				/* monitor close() */
	int wakeup_fd;				/* monitor close() */
};

/*
 * Stream representation within consumer.
 */
struct lttng_ust_ctl_consumer_stream {
	struct lttng_ust_ring_buffer *buf;
	struct lttng_ust_ctl_consumer_channel *chan;
	int shm_fd, wait_fd, wakeup_fd;
	int cpu;
	uint64_t memory_map_size;
	void *memory_map_addr;
};

#define LTTNG_UST_CTL_COUNTER_ATTR_DIMENSION_MAX 8
struct lttng_ust_ctl_counter_attr {
	enum lttng_ust_ctl_counter_arithmetic arithmetic;
	enum lttng_ust_ctl_counter_bitness bitness;
	uint32_t nr_dimensions;
	int64_t global_sum_step;
	struct lttng_ust_ctl_counter_dimension dimensions[LTTNG_UST_CTL_COUNTER_ATTR_DIMENSION_MAX];
	bool coalesce_hits;
};

/*
 * Counter representation within daemon.
 */
struct lttng_ust_ctl_daemon_counter {
	struct lib_counter *counter;
	const struct lttng_counter_ops *ops;
	struct lttng_ust_ctl_counter_attr *attr;	/* initial attributes */
};

/*
 * Evaluates to false if transaction begins, true if it has failed due to SIGBUS.
 * The entire transaction must complete before the current function returns.
 * A transaction can contain 0 or more tracked ranges as sigbus begin/end pairs.
 */
#define sigbus_begin() \
({ \
	assert(!lttng_ust_sigbus_state.jmp_ready); \
	if (!lttng_ust_sigbus_state.head.next) { \
		/* \
		 * Lazy init because static list initialisation is \
		 * problematic for TLS variable. \
		 */ \
		CDS_INIT_LIST_HEAD(&lttng_ust_sigbus_state.head); \
	} \
	if (sigsetjmp(lttng_ust_sigbus_state.sj_env, 1)) { \
		/* SIGBUS. */ \
		CMM_STORE_SHARED(lttng_ust_sigbus_state.jmp_ready, 0); \
		true; \
	} \
	cmm_barrier(); \
	CMM_STORE_SHARED(lttng_ust_sigbus_state.jmp_ready, 1); \
	false; \
})

static void sigbus_end(void)
{
	assert(lttng_ust_sigbus_state.jmp_ready);
	cmm_barrier();
	CMM_STORE_SHARED(lttng_ust_sigbus_state.jmp_ready, 0);
}

static
void lttng_ust_sigbus_add_range(struct lttng_ust_sigbus_range *range, void *start, size_t len)
{
	range->start = start;
	range->end = (char *)start + len;
	cds_list_add_rcu(&range->node, &lttng_ust_sigbus_state.head);
	cmm_barrier();
}

static
void lttng_ust_sigbus_del_range(struct lttng_ust_sigbus_range *range)
{
	cmm_barrier();
	cds_list_del_rcu(&range->node);
}

void lttng_ust_ctl_sigbus_handle(void *addr)
{
	struct lttng_ust_sigbus_range *range;

	if (!CMM_LOAD_SHARED(lttng_ust_sigbus_state.jmp_ready))
		return;
	cds_list_for_each_entry_rcu(range, &lttng_ust_sigbus_state.head, node) {
		if (addr < range->start || addr >= range->end)
			continue;
		siglongjmp(lttng_ust_sigbus_state.sj_env, 1);
	}
}

int lttng_ust_ctl_release_handle(int sock, int handle)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;

	if (sock < 0 || handle < 0)
		return 0;
	memset(&lum, 0, sizeof(lum));
	lum.handle = handle;
	lum.cmd = LTTNG_UST_ABI_RELEASE;
	return ustcomm_send_app_cmd(sock, &lum, &lur);
}

/*
 * If sock is negative, it means we don't have to notify the other side
 * (e.g. application has already vanished).
 */
int lttng_ust_ctl_release_object(int sock, struct lttng_ust_abi_object_data *data)
{
	int ret;

	if (!data)
		return -EINVAL;

	switch (data->type) {
	case LTTNG_UST_ABI_OBJECT_TYPE_CHANNEL:
		if (data->u.channel.wakeup_fd >= 0) {
			ret = close(data->u.channel.wakeup_fd);
			if (ret < 0) {
				ret = -errno;
				return ret;
			}
			data->u.channel.wakeup_fd = -1;
		}
		free(data->u.channel.data);
		data->u.channel.data = NULL;
		break;
	case LTTNG_UST_ABI_OBJECT_TYPE_STREAM:
		if (data->u.stream.shm_fd >= 0) {
			ret = close(data->u.stream.shm_fd);
			if (ret < 0) {
				ret = -errno;
				return ret;
			}
			data->u.stream.shm_fd = -1;
		}
		if (data->u.stream.wakeup_fd >= 0) {
			ret = close(data->u.stream.wakeup_fd);
			if (ret < 0) {
				ret = -errno;
				return ret;
			}
			data->u.stream.wakeup_fd = -1;
		}
		break;
	case LTTNG_UST_ABI_OBJECT_TYPE_EVENT:
	case LTTNG_UST_ABI_OBJECT_TYPE_CONTEXT:
	case LTTNG_UST_ABI_OBJECT_TYPE_EVENT_NOTIFIER_GROUP:
	case LTTNG_UST_ABI_OBJECT_TYPE_EVENT_NOTIFIER:
		break;
	case LTTNG_UST_ABI_OBJECT_TYPE_COUNTER:
		free(data->u.counter.data);
		data->u.counter.data = NULL;
		break;
	case LTTNG_UST_ABI_OBJECT_TYPE_COUNTER_GLOBAL:
		if (data->u.counter_global.shm_fd >= 0) {
			ret = close(data->u.counter_global.shm_fd);
			if (ret < 0) {
				ret = -errno;
				return ret;
			}
			data->u.counter_global.shm_fd = -1;
		}
		break;
	case LTTNG_UST_ABI_OBJECT_TYPE_COUNTER_CPU:
		if (data->u.counter_cpu.shm_fd >= 0) {
			ret = close(data->u.counter_cpu.shm_fd);
			if (ret < 0) {
				ret = -errno;
				return ret;
			}
			data->u.counter_cpu.shm_fd = -1;
		}
		break;
	default:
		assert(0);
	}
	return lttng_ust_ctl_release_handle(sock, data->handle);
}

/*
 * Send registration done packet to the application.
 */
int lttng_ust_ctl_register_done(int sock)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret;

	DBG("Sending register done command to %d", sock);
	memset(&lum, 0, sizeof(lum));
	lum.handle = LTTNG_UST_ABI_ROOT_HANDLE;
	lum.cmd = LTTNG_UST_ABI_REGISTER_DONE;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	return 0;
}

/*
 * returns session handle.
 */
int lttng_ust_ctl_create_session(int sock)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret, session_handle;

	/* Create session */
	memset(&lum, 0, sizeof(lum));
	lum.handle = LTTNG_UST_ABI_ROOT_HANDLE;
	lum.cmd = LTTNG_UST_ABI_SESSION;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	session_handle = lur.ret_val;
	DBG("received session handle %u", session_handle);
	return session_handle;
}

int lttng_ust_ctl_create_event(int sock, struct lttng_ust_abi_event *ev,
		struct lttng_ust_abi_object_data *channel_data,
		struct lttng_ust_abi_object_data **_event_data)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	struct lttng_ust_abi_object_data *event_data;
	int ret;

	if (!channel_data || !_event_data)
		return -EINVAL;

	event_data = zmalloc(sizeof(*event_data));
	if (!event_data)
		return -ENOMEM;
	event_data->type = LTTNG_UST_ABI_OBJECT_TYPE_EVENT;
	memset(&lum, 0, sizeof(lum));
	lum.handle = channel_data->handle;
	lum.cmd = LTTNG_UST_ABI_EVENT;
	strncpy(lum.u.event.name, ev->name,
		LTTNG_UST_ABI_SYM_NAME_LEN);
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

/*
 * Protocol for LTTNG_UST_ABI_CONTEXT command:
 *
 * - send:     struct ustcomm_ust_msg
 * - send:     var len ctx_name
 * - receive:  struct ustcomm_ust_reply
 *
 * TODO: At the next breaking protocol bump, we should indicate the total
 * command message length as part of a message header so that the protocol can
 * recover from invalid command errors.
 */
int lttng_ust_ctl_add_context(int sock, struct lttng_ust_context_attr *ctx,
		struct lttng_ust_abi_object_data *obj_data,
		struct lttng_ust_abi_object_data **_context_data)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	struct lttng_ust_abi_object_data *context_data = NULL;
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
	context_data->type = LTTNG_UST_ABI_OBJECT_TYPE_CONTEXT;
	memset(&lum, 0, sizeof(lum));
	lum.handle = obj_data->handle;
	lum.cmd = LTTNG_UST_ABI_CONTEXT;

	lum.u.context.ctx = ctx->ctx;
	switch (ctx->ctx) {
	case LTTNG_UST_ABI_CONTEXT_PERF_THREAD_COUNTER:
		lum.u.context.u.perf_counter = ctx->u.perf_counter;
		break;
	case LTTNG_UST_ABI_CONTEXT_APP_CONTEXT:
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
		if (ret == -EINVAL) {
			/*
			 * Command unknown from remote end. The communication socket is
			 * now out-of-sync and needs to be shutdown.
			 */
			(void) ustcomm_shutdown_unix_sock(sock);
		}
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

/*
 * Protocol for LTTNG_UST_ABI_FILTER command:
 *
 * - send:     struct ustcomm_ust_msg
 * - send:     var len bytecode
 * - receive:  struct ustcomm_ust_reply
 *
 * TODO: At the next breaking protocol bump, we should indicate the total
 * command message length as part of a message header so that the protocol can
 * recover from invalid command errors.
 */
int lttng_ust_ctl_set_filter(int sock, struct lttng_ust_abi_filter_bytecode *bytecode,
		struct lttng_ust_abi_object_data *obj_data)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret;

	if (!obj_data)
		return -EINVAL;

	memset(&lum, 0, sizeof(lum));
	lum.handle = obj_data->handle;
	lum.cmd = LTTNG_UST_ABI_FILTER;
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
	ret = ustcomm_recv_app_reply(sock, &lur, lum.handle, lum.cmd);
	if (ret == -EINVAL) {
		/*
		 * Command unknown from remote end. The communication socket is
		 * now out-of-sync and needs to be shutdown.
		 */
		(void) ustcomm_shutdown_unix_sock(sock);
	}
	return ret;
}

/*
 * Protocol for LTTNG_UST_ABI_CAPTURE command:
 *
 * - send:     struct ustcomm_ust_msg
 * - receive:  struct ustcomm_ust_reply
 * - send:     var len bytecode
 * - receive:  struct ustcomm_ust_reply (actual command return code)
 */
int lttng_ust_ctl_set_capture(int sock, struct lttng_ust_abi_capture_bytecode *bytecode,
		struct lttng_ust_abi_object_data *obj_data)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret;

	if (!obj_data)
		return -EINVAL;

	memset(&lum, 0, sizeof(lum));
	lum.handle = obj_data->handle;
	lum.cmd = LTTNG_UST_ABI_CAPTURE;
	lum.u.capture.data_size = bytecode->len;
	lum.u.capture.reloc_offset = bytecode->reloc_offset;
	lum.u.capture.seqnum = bytecode->seqnum;

	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
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

/*
 * Protocol for LTTNG_UST_ABI_EXCLUSION command:
 *
 * - send:     struct ustcomm_ust_msg
 * - send:     var len exclusion names
 * - receive:  struct ustcomm_ust_reply
 *
 * TODO: At the next breaking protocol bump, we should indicate the total
 * command message length as part of a message header so that the protocol can
 * recover from invalid command errors.
 */
int lttng_ust_ctl_set_exclusion(int sock, struct lttng_ust_abi_event_exclusion *exclusion,
		struct lttng_ust_abi_object_data *obj_data)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret;

	if (!obj_data) {
		return -EINVAL;
	}

	memset(&lum, 0, sizeof(lum));
	lum.handle = obj_data->handle;
	lum.cmd = LTTNG_UST_ABI_EXCLUSION;
	lum.u.exclusion.count = exclusion->count;

	ret = ustcomm_send_app_msg(sock, &lum);
	if (ret) {
		return ret;
	}

	/* send var len exclusion names */
	ret = ustcomm_send_unix_sock(sock,
			exclusion->names,
			exclusion->count * LTTNG_UST_ABI_SYM_NAME_LEN);
	if (ret < 0) {
		return ret;
	}
	if (ret != exclusion->count * LTTNG_UST_ABI_SYM_NAME_LEN) {
		return -EINVAL;
	}
	ret = ustcomm_recv_app_reply(sock, &lur, lum.handle, lum.cmd);
	if (ret == -EINVAL) {
		/*
		 * Command unknown from remote end. The communication socket is
		 * now out-of-sync and needs to be shutdown.
		 */
		(void) ustcomm_shutdown_unix_sock(sock);
	}
	return ret;
}

/* Enable event, channel and session ioctl */
int lttng_ust_ctl_enable(int sock, struct lttng_ust_abi_object_data *object)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret;

	if (!object)
		return -EINVAL;

	memset(&lum, 0, sizeof(lum));
	lum.handle = object->handle;
	lum.cmd = LTTNG_UST_ABI_ENABLE;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	DBG("enabled handle %u", object->handle);
	return 0;
}

/* Disable event, channel and session ioctl */
int lttng_ust_ctl_disable(int sock, struct lttng_ust_abi_object_data *object)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret;

	if (!object)
		return -EINVAL;

	memset(&lum, 0, sizeof(lum));
	lum.handle = object->handle;
	lum.cmd = LTTNG_UST_ABI_DISABLE;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	DBG("disable handle %u", object->handle);
	return 0;
}

int lttng_ust_ctl_start_session(int sock, int handle)
{
	struct lttng_ust_abi_object_data obj;

	obj.handle = handle;
	return lttng_ust_ctl_enable(sock, &obj);
}

int lttng_ust_ctl_stop_session(int sock, int handle)
{
	struct lttng_ust_abi_object_data obj;

	obj.handle = handle;
	return lttng_ust_ctl_disable(sock, &obj);
}

/*
 * Protocol for LTTNG_UST_ABI_EVENT_NOTIFIER_GROUP_CREATE command:
 *
 * - send:     struct ustcomm_ust_msg
 * - receive:  struct ustcomm_ust_reply
 * - send:     file descriptor
 * - receive:  struct ustcomm_ust_reply (actual command return code)
 */
int lttng_ust_ctl_create_event_notifier_group(int sock, int pipe_fd,
		struct lttng_ust_abi_object_data **_event_notifier_group_data)
{
	struct lttng_ust_abi_object_data *event_notifier_group_data;
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	ssize_t len;
	int ret;

	if (!_event_notifier_group_data)
		return -EINVAL;

	event_notifier_group_data = zmalloc(sizeof(*event_notifier_group_data));
	if (!event_notifier_group_data)
		return -ENOMEM;

	event_notifier_group_data->type = LTTNG_UST_ABI_OBJECT_TYPE_EVENT_NOTIFIER_GROUP;

	memset(&lum, 0, sizeof(lum));
	lum.handle = LTTNG_UST_ABI_ROOT_HANDLE;
	lum.cmd = LTTNG_UST_ABI_EVENT_NOTIFIER_GROUP_CREATE;

	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		goto error;

	/* Send event_notifier notification pipe. */
	len = ustcomm_send_fds_unix_sock(sock, &pipe_fd, 1);
	if (len <= 0) {
		ret = len;
		goto error;
	}

	ret = ustcomm_recv_app_reply(sock, &lur, lum.handle, lum.cmd);
	if (ret)
		goto error;

	event_notifier_group_data->handle = lur.ret_val;
	DBG("received event_notifier group handle %d", event_notifier_group_data->handle);

	*_event_notifier_group_data = event_notifier_group_data;

	ret = 0;
	goto end;
error:
	free(event_notifier_group_data);

end:
	return ret;
}

/*
 * Protocol for LTTNG_UST_ABI_EVENT_NOTIFIER_CREATE command:
 *
 * - send:     struct ustcomm_ust_msg
 * - receive:  struct ustcomm_ust_reply
 * - send:     struct lttng_ust_abi_event_notifier
 * - receive:  struct ustcomm_ust_reply (actual command return code)
 */
int lttng_ust_ctl_create_event_notifier(int sock, struct lttng_ust_abi_event_notifier *event_notifier,
		struct lttng_ust_abi_object_data *event_notifier_group,
		struct lttng_ust_abi_object_data **_event_notifier_data)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	struct lttng_ust_abi_object_data *event_notifier_data;
	ssize_t len;
	int ret;

	if (!event_notifier_group || !_event_notifier_data)
		return -EINVAL;

	event_notifier_data = zmalloc(sizeof(*event_notifier_data));
	if (!event_notifier_data)
		return -ENOMEM;

	event_notifier_data->type = LTTNG_UST_ABI_OBJECT_TYPE_EVENT_NOTIFIER;

	memset(&lum, 0, sizeof(lum));
	lum.handle = event_notifier_group->handle;
	lum.cmd = LTTNG_UST_ABI_EVENT_NOTIFIER_CREATE;
	lum.u.event_notifier.len = sizeof(*event_notifier);

	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret) {
		free(event_notifier_data);
		return ret;
	}
	/* Send struct lttng_ust_abi_event_notifier */
	len = ustcomm_send_unix_sock(sock, event_notifier, sizeof(*event_notifier));
	if (len != sizeof(*event_notifier)) {
		free(event_notifier_data);
		if (len < 0)
			return len;
		else
			return -EIO;
	}
	ret = ustcomm_recv_app_reply(sock, &lur, lum.handle, lum.cmd);
	if (ret) {
		free(event_notifier_data);
		return ret;
	}
	event_notifier_data->handle = lur.ret_val;
	DBG("received event_notifier handle %u", event_notifier_data->handle);
	*_event_notifier_data = event_notifier_data;

	return ret;
}

int lttng_ust_ctl_tracepoint_list(int sock)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret, tp_list_handle;

	memset(&lum, 0, sizeof(lum));
	lum.handle = LTTNG_UST_ABI_ROOT_HANDLE;
	lum.cmd = LTTNG_UST_ABI_TRACEPOINT_LIST;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	tp_list_handle = lur.ret_val;
	DBG("received tracepoint list handle %u", tp_list_handle);
	return tp_list_handle;
}

int lttng_ust_ctl_tracepoint_list_get(int sock, int tp_list_handle,
		struct lttng_ust_abi_tracepoint_iter *iter)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret;

	if (!iter)
		return -EINVAL;

	memset(&lum, 0, sizeof(lum));
	lum.handle = tp_list_handle;
	lum.cmd = LTTNG_UST_ABI_TRACEPOINT_LIST_GET;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	DBG("received tracepoint list entry name %s loglevel %d",
		lur.u.tracepoint.name,
		lur.u.tracepoint.loglevel);
	memcpy(iter, &lur.u.tracepoint, sizeof(*iter));
	return 0;
}

int lttng_ust_ctl_tracepoint_field_list(int sock)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret, tp_field_list_handle;

	memset(&lum, 0, sizeof(lum));
	lum.handle = LTTNG_UST_ABI_ROOT_HANDLE;
	lum.cmd = LTTNG_UST_ABI_TRACEPOINT_FIELD_LIST;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	tp_field_list_handle = lur.ret_val;
	DBG("received tracepoint field list handle %u", tp_field_list_handle);
	return tp_field_list_handle;
}

int lttng_ust_ctl_tracepoint_field_list_get(int sock, int tp_field_list_handle,
		struct lttng_ust_abi_field_iter *iter)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret;
	ssize_t len;

	if (!iter)
		return -EINVAL;

	memset(&lum, 0, sizeof(lum));
	lum.handle = tp_field_list_handle;
	lum.cmd = LTTNG_UST_ABI_TRACEPOINT_FIELD_LIST_GET;
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

int lttng_ust_ctl_tracer_version(int sock, struct lttng_ust_abi_tracer_version *v)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret;

	if (!v)
		return -EINVAL;

	memset(&lum, 0, sizeof(lum));
	lum.handle = LTTNG_UST_ABI_ROOT_HANDLE;
	lum.cmd = LTTNG_UST_ABI_TRACER_VERSION;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	memcpy(v, &lur.u.version, sizeof(*v));
	DBG("received tracer version");
	return 0;
}

int lttng_ust_ctl_wait_quiescent(int sock)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret;

	memset(&lum, 0, sizeof(lum));
	lum.handle = LTTNG_UST_ABI_ROOT_HANDLE;
	lum.cmd = LTTNG_UST_ABI_WAIT_QUIESCENT;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	DBG("waited for quiescent state");
	return 0;
}

int lttng_ust_ctl_calibrate(int sock __attribute__((unused)),
		struct lttng_ust_abi_calibrate *calibrate)
{
	if (!calibrate)
		return -EINVAL;

	return -ENOSYS;
}

int lttng_ust_ctl_sock_flush_buffer(int sock, struct lttng_ust_abi_object_data *object)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret;

	if (!object)
		return -EINVAL;

	memset(&lum, 0, sizeof(lum));
	lum.handle = object->handle;
	lum.cmd = LTTNG_UST_ABI_FLUSH_BUFFER;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	DBG("flushed buffer handle %u", object->handle);
	return 0;
}

static
int lttng_ust_ctl_send_channel(int sock,
		enum lttng_ust_abi_chan_type type,
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
int lttng_ust_ctl_send_stream(int sock,
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

int lttng_ust_ctl_recv_channel_from_consumer(int sock,
		struct lttng_ust_abi_object_data **_channel_data)
{
	struct lttng_ust_abi_object_data *channel_data;
	ssize_t len;
	int wakeup_fd;
	int ret;

	channel_data = zmalloc(sizeof(*channel_data));
	if (!channel_data) {
		ret = -ENOMEM;
		goto error_alloc;
	}
	channel_data->type = LTTNG_UST_ABI_OBJECT_TYPE_CHANNEL;
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

int lttng_ust_ctl_recv_stream_from_consumer(int sock,
		struct lttng_ust_abi_object_data **_stream_data)
{
	struct lttng_ust_abi_object_data *stream_data;
	ssize_t len;
	int ret;
	int fds[2];

	stream_data = zmalloc(sizeof(*stream_data));
	if (!stream_data) {
		ret = -ENOMEM;
		goto error_alloc;
	}

	stream_data->type = LTTNG_UST_ABI_OBJECT_TYPE_STREAM;
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

/*
 * Protocol for LTTNG_UST_ABI_CHANNEL command:
 *
 * - send:     struct ustcomm_ust_msg
 * - send:     file descriptors and channel data
 * - receive:  struct ustcomm_ust_reply
 *
 * TODO: At the next breaking protocol bump, we should indicate the total
 * command message length as part of a message header so that the protocol can
 * recover from invalid command errors.
 */
int lttng_ust_ctl_send_channel_to_ust(int sock, int session_handle,
		struct lttng_ust_abi_object_data *channel_data)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret;

	if (!channel_data)
		return -EINVAL;

	memset(&lum, 0, sizeof(lum));
	lum.handle = session_handle;
	lum.cmd = LTTNG_UST_ABI_CHANNEL;
	lum.u.channel.len = channel_data->size;
	lum.u.channel.type = channel_data->u.channel.type;
	ret = ustcomm_send_app_msg(sock, &lum);
	if (ret)
		return ret;

	ret = lttng_ust_ctl_send_channel(sock,
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
	} else if (ret == -EINVAL) {
		/*
		 * Command unknown from remote end. The communication socket is
		 * now out-of-sync and needs to be shutdown.
		 */
		(void) ustcomm_shutdown_unix_sock(sock);
	}
	return ret;
}

/*
 * Protocol for LTTNG_UST_ABI_STREAM command:
 *
 * - send:     struct ustcomm_ust_msg
 * - send:     file descriptors and stream data
 * - receive:  struct ustcomm_ust_reply
 *
 * TODO: At the next breaking protocol bump, we should indicate the total
 * command message length as part of a message header so that the protocol can
 * recover from invalid command errors.
 */
int lttng_ust_ctl_send_stream_to_ust(int sock,
		struct lttng_ust_abi_object_data *channel_data,
		struct lttng_ust_abi_object_data *stream_data)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret;

	memset(&lum, 0, sizeof(lum));
	lum.handle = channel_data->handle;
	lum.cmd = LTTNG_UST_ABI_STREAM;
	lum.u.stream.len = stream_data->size;
	lum.u.stream.stream_nr = stream_data->u.stream.stream_nr;
	ret = ustcomm_send_app_msg(sock, &lum);
	if (ret)
		return ret;

	assert(stream_data);
	assert(stream_data->type == LTTNG_UST_ABI_OBJECT_TYPE_STREAM);

	ret = lttng_ust_ctl_send_stream(sock,
			stream_data->u.stream.stream_nr,
			stream_data->size,
			stream_data->u.stream.shm_fd,
			stream_data->u.stream.wakeup_fd, 1);
	if (ret)
		return ret;
	ret = ustcomm_recv_app_reply(sock, &lur, lum.handle, lum.cmd);
	if (ret == -EINVAL) {
		/*
		 * Command unknown from remote end. The communication socket is
		 * now out-of-sync and needs to be shutdown.
		 */
		(void) ustcomm_shutdown_unix_sock(sock);
	}
	return ret;
}

int lttng_ust_ctl_duplicate_ust_object_data(struct lttng_ust_abi_object_data **dest,
                struct lttng_ust_abi_object_data *src)
{
	struct lttng_ust_abi_object_data *obj;
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
	case LTTNG_UST_ABI_OBJECT_TYPE_CHANNEL:
	{
		obj->u.channel.type = src->u.channel.type;
		if (src->u.channel.wakeup_fd >= 0) {
			obj->u.channel.wakeup_fd =
				dup(src->u.channel.wakeup_fd);
			if (obj->u.channel.wakeup_fd < 0) {
				ret = -errno;
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

	case LTTNG_UST_ABI_OBJECT_TYPE_STREAM:
	{
		obj->u.stream.stream_nr = src->u.stream.stream_nr;
		if (src->u.stream.wakeup_fd >= 0) {
			obj->u.stream.wakeup_fd =
				dup(src->u.stream.wakeup_fd);
			if (obj->u.stream.wakeup_fd < 0) {
				ret = -errno;
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
				ret = -errno;
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

	case LTTNG_UST_ABI_OBJECT_TYPE_COUNTER:
	{
		obj->u.counter.data = zmalloc(obj->size);
		if (!obj->u.counter.data) {
			ret = -ENOMEM;
			goto error_type;
		}
		memcpy(obj->u.counter.data, src->u.counter.data, obj->size);
		break;
	}

	case LTTNG_UST_ABI_OBJECT_TYPE_COUNTER_GLOBAL:
	{
		if (src->u.counter_global.shm_fd >= 0) {
			obj->u.counter_global.shm_fd =
				dup(src->u.counter_global.shm_fd);
			if (obj->u.counter_global.shm_fd < 0) {
				ret = -errno;
				goto error_type;
			}
		}
		break;
	}

	case LTTNG_UST_ABI_OBJECT_TYPE_COUNTER_CPU:
	{
		obj->u.counter_cpu.cpu_nr = src->u.counter_cpu.cpu_nr;
		if (src->u.counter_cpu.shm_fd >= 0) {
			obj->u.counter_cpu.shm_fd =
				dup(src->u.counter_cpu.shm_fd);
			if (obj->u.counter_cpu.shm_fd < 0) {
				ret = -errno;
				goto error_type;
			}
		}
		break;
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

int lttng_ust_ctl_get_nr_stream_per_channel(void)
{
	return num_possible_cpus();
}

struct lttng_ust_ctl_consumer_channel *
	lttng_ust_ctl_create_channel(struct lttng_ust_ctl_consumer_channel_attr *attr,
		const int *stream_fds, int nr_stream_fds)
{
	struct lttng_ust_ctl_consumer_channel *chan;
	const char *transport_name;
	struct lttng_transport *transport;

	switch (attr->type) {
	case LTTNG_UST_ABI_CHAN_PER_CPU:
		if (attr->output == LTTNG_UST_ABI_MMAP) {
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
	case LTTNG_UST_ABI_CHAN_METADATA:
		if (attr->output == LTTNG_UST_ABI_MMAP)
			transport_name = "relay-metadata-mmap";
		else
			return NULL;
		break;
	default:
		transport_name = "<unknown>";
		return NULL;
	}

	transport = lttng_ust_transport_find(transport_name);
	if (!transport) {
		DBG("LTTng transport %s not found\n",
			transport_name);
		return NULL;
	}

	chan = zmalloc(sizeof(*chan));
	if (!chan)
		return NULL;

	chan->chan = transport->ops.priv->channel_create(transport_name, NULL,
			attr->subbuf_size, attr->num_subbuf,
			attr->switch_timer_interval,
			attr->read_timer_interval,
			attr->uuid, attr->chan_id,
			stream_fds, nr_stream_fds,
			attr->blocking_timeout);
	if (!chan->chan) {
		goto chan_error;
	}
	chan->chan->ops = &transport->ops;
	memcpy(&chan->attr, attr, sizeof(chan->attr));
	chan->wait_fd = lttng_ust_ctl_channel_get_wait_fd(chan);
	chan->wakeup_fd = lttng_ust_ctl_channel_get_wakeup_fd(chan);
	return chan;

chan_error:
	free(chan);
	return NULL;
}

void lttng_ust_ctl_destroy_channel(struct lttng_ust_ctl_consumer_channel *chan)
{
	(void) lttng_ust_ctl_channel_close_wait_fd(chan);
	(void) lttng_ust_ctl_channel_close_wakeup_fd(chan);
	chan->chan->ops->priv->channel_destroy(chan->chan);
	free(chan);
}

int lttng_ust_ctl_send_channel_to_sessiond(int sock,
		struct lttng_ust_ctl_consumer_channel *channel)
{
	struct shm_object_table *table;

	table = channel->chan->priv->rb_chan->handle->table;
	if (table->size <= 0)
		return -EINVAL;
	return lttng_ust_ctl_send_channel(sock,
			channel->attr.type,
			table->objects[0].memory_map,
			table->objects[0].memory_map_size,
			channel->wakeup_fd,
			0);
}

int lttng_ust_ctl_send_stream_to_sessiond(int sock,
		struct lttng_ust_ctl_consumer_stream *stream)
{
	if (!stream)
		return lttng_ust_ctl_send_stream(sock, -1U, -1U, -1, -1, 0);

	return lttng_ust_ctl_send_stream(sock,
			stream->cpu,
			stream->memory_map_size,
			stream->shm_fd, stream->wakeup_fd,
			0);
}

int lttng_ust_ctl_write_metadata_to_channel(
		struct lttng_ust_ctl_consumer_channel *channel,
		const char *metadata_str,	/* NOT null-terminated */
		size_t len)			/* metadata length */
{
	struct lttng_ust_ring_buffer_ctx ctx;
	struct lttng_ust_channel_buffer *lttng_chan_buf = channel->chan;
	struct lttng_ust_ring_buffer_channel *rb_chan = lttng_chan_buf->priv->rb_chan;
	const char *str = metadata_str;
	int ret = 0, waitret;
	size_t reserve_len, pos;

	for (pos = 0; pos < len; pos += reserve_len) {
		reserve_len = min_t(size_t,
				lttng_chan_buf->ops->priv->packet_avail_size(lttng_chan_buf),
				len - pos);
		lttng_ust_ring_buffer_ctx_init(&ctx, rb_chan, reserve_len, sizeof(char), NULL);
		/*
		 * We don't care about metadata buffer's records lost
		 * count, because we always retry here. Report error if
		 * we need to bail out after timeout or being
		 * interrupted.
		 */
		waitret = wait_cond_interruptible_timeout(
			({
				ret = lttng_chan_buf->ops->event_reserve(&ctx);
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
		lttng_chan_buf->ops->event_write(&ctx, &str[pos], reserve_len, 1);
		lttng_chan_buf->ops->event_commit(&ctx);
	}
end:
	return ret;
}

/*
 * Write at most one packet in the channel.
 * Returns the number of bytes written on success, < 0 on error.
 */
ssize_t lttng_ust_ctl_write_one_packet_to_channel(
		struct lttng_ust_ctl_consumer_channel *channel,
		const char *metadata_str,	/* NOT null-terminated */
		size_t len)			/* metadata length */
{
	struct lttng_ust_ring_buffer_ctx ctx;
	struct lttng_ust_channel_buffer *lttng_chan_buf = channel->chan;
	struct lttng_ust_ring_buffer_channel *rb_chan = lttng_chan_buf->priv->rb_chan;
	const char *str = metadata_str;
	ssize_t reserve_len;
	int ret;

	reserve_len = min_t(ssize_t,
			lttng_chan_buf->ops->priv->packet_avail_size(lttng_chan_buf),
			len);
	lttng_ust_ring_buffer_ctx_init(&ctx, rb_chan, reserve_len, sizeof(char), NULL);
	ret = lttng_chan_buf->ops->event_reserve(&ctx);
	if (ret != 0) {
		DBG("LTTng: event reservation failed");
		assert(ret < 0);
		reserve_len = ret;
		goto end;
	}
	lttng_chan_buf->ops->event_write(&ctx, str, reserve_len, 1);
	lttng_chan_buf->ops->event_commit(&ctx);

end:
	return reserve_len;
}

int lttng_ust_ctl_channel_close_wait_fd(struct lttng_ust_ctl_consumer_channel *consumer_chan)
{
	struct lttng_ust_ring_buffer_channel *chan;
	int ret;

	chan = consumer_chan->chan->priv->rb_chan;
	ret = ring_buffer_channel_close_wait_fd(&chan->backend.config,
			chan, chan->handle);
	if (!ret)
		consumer_chan->wait_fd = -1;
	return ret;
}

int lttng_ust_ctl_channel_close_wakeup_fd(struct lttng_ust_ctl_consumer_channel *consumer_chan)
{
	struct lttng_ust_ring_buffer_channel *chan;
	int ret;

	chan = consumer_chan->chan->priv->rb_chan;
	ret = ring_buffer_channel_close_wakeup_fd(&chan->backend.config,
			chan, chan->handle);
	if (!ret)
		consumer_chan->wakeup_fd = -1;
	return ret;
}

int lttng_ust_ctl_stream_close_wait_fd(struct lttng_ust_ctl_consumer_stream *stream)
{
	struct lttng_ust_ring_buffer_channel *chan;

	chan = stream->chan->chan->priv->rb_chan;
	return ring_buffer_stream_close_wait_fd(&chan->backend.config,
			chan, chan->handle, stream->cpu);
}

int lttng_ust_ctl_stream_close_wakeup_fd(struct lttng_ust_ctl_consumer_stream *stream)
{
	struct lttng_ust_ring_buffer_channel *chan;

	chan = stream->chan->chan->priv->rb_chan;
	return ring_buffer_stream_close_wakeup_fd(&chan->backend.config,
			chan, chan->handle, stream->cpu);
}

struct lttng_ust_ctl_consumer_stream *
	lttng_ust_ctl_create_stream(struct lttng_ust_ctl_consumer_channel *channel,
			int cpu)
{
	struct lttng_ust_ctl_consumer_stream *stream;
	struct lttng_ust_shm_handle *handle;
	struct lttng_ust_ring_buffer_channel *rb_chan;
	int shm_fd, wait_fd, wakeup_fd;
	uint64_t memory_map_size;
	void *memory_map_addr;
	struct lttng_ust_ring_buffer *buf;
	int ret;

	if (!channel)
		return NULL;
	rb_chan = channel->chan->priv->rb_chan;
	handle = rb_chan->handle;
	if (!handle)
		return NULL;

	buf = channel_get_ring_buffer(&rb_chan->backend.config,
		rb_chan, cpu, handle, &shm_fd, &wait_fd,
		&wakeup_fd, &memory_map_size, &memory_map_addr);
	if (!buf)
		return NULL;
	ret = lib_ring_buffer_open_read(buf, handle);
	if (ret)
		return NULL;

	stream = zmalloc(sizeof(*stream));
	if (!stream)
		goto alloc_error;
	stream->buf = buf;
	stream->chan = channel;
	stream->shm_fd = shm_fd;
	stream->wait_fd = wait_fd;
	stream->wakeup_fd = wakeup_fd;
	stream->memory_map_size = memory_map_size;
	stream->memory_map_addr = memory_map_addr;
	stream->cpu = cpu;
	return stream;

alloc_error:
	return NULL;
}

void lttng_ust_ctl_destroy_stream(struct lttng_ust_ctl_consumer_stream *stream)
{
	struct lttng_ust_ring_buffer *buf;
	struct lttng_ust_ctl_consumer_channel *consumer_chan;

	assert(stream);
	buf = stream->buf;
	consumer_chan = stream->chan;
	(void) lttng_ust_ctl_stream_close_wait_fd(stream);
	(void) lttng_ust_ctl_stream_close_wakeup_fd(stream);
	lib_ring_buffer_release_read(buf, consumer_chan->chan->priv->rb_chan->handle);
	free(stream);
}

int lttng_ust_ctl_channel_get_wait_fd(struct lttng_ust_ctl_consumer_channel *chan)
{
	if (!chan)
		return -EINVAL;
	return shm_get_wait_fd(chan->chan->priv->rb_chan->handle,
		&chan->chan->priv->rb_chan->handle->chan._ref);
}

int lttng_ust_ctl_channel_get_wakeup_fd(struct lttng_ust_ctl_consumer_channel *chan)
{
	if (!chan)
		return -EINVAL;
	return shm_get_wakeup_fd(chan->chan->priv->rb_chan->handle,
		&chan->chan->priv->rb_chan->handle->chan._ref);
}

int lttng_ust_ctl_stream_get_wait_fd(struct lttng_ust_ctl_consumer_stream *stream)
{
	struct lttng_ust_ring_buffer *buf;
	struct lttng_ust_ctl_consumer_channel *consumer_chan;

	if (!stream)
		return -EINVAL;
	buf = stream->buf;
	consumer_chan = stream->chan;
	return shm_get_wait_fd(consumer_chan->chan->priv->rb_chan->handle, &buf->self._ref);
}

int lttng_ust_ctl_stream_get_wakeup_fd(struct lttng_ust_ctl_consumer_stream *stream)
{
	struct lttng_ust_ring_buffer *buf;
	struct lttng_ust_ctl_consumer_channel *consumer_chan;

	if (!stream)
		return -EINVAL;
	buf = stream->buf;
	consumer_chan = stream->chan;
	return shm_get_wakeup_fd(consumer_chan->chan->priv->rb_chan->handle, &buf->self._ref);
}

/* For mmap mode, readable without "get" operation */

void *lttng_ust_ctl_get_mmap_base(struct lttng_ust_ctl_consumer_stream *stream)
{
	struct lttng_ust_ring_buffer *buf;
	struct lttng_ust_ctl_consumer_channel *consumer_chan;
	struct lttng_ust_sigbus_range range;
	void *p;

	if (!stream)
		return NULL;
	buf = stream->buf;
	consumer_chan = stream->chan;
	if (sigbus_begin())
		return NULL;
	lttng_ust_sigbus_add_range(&range, stream->memory_map_addr,
				stream->memory_map_size);
	p = shmp(consumer_chan->chan->priv->rb_chan->handle, buf->backend.memory_map);
	lttng_ust_sigbus_del_range(&range);
	sigbus_end();
	return p;	/* Users of this pointer should check for sigbus. */
}

/* returns the length to mmap. */
int lttng_ust_ctl_get_mmap_len(struct lttng_ust_ctl_consumer_stream *stream,
		unsigned long *len)
{
	struct lttng_ust_ctl_consumer_channel *consumer_chan;
	unsigned long mmap_buf_len;
	struct lttng_ust_ring_buffer_channel *rb_chan;

	if (!stream)
		return -EINVAL;
	consumer_chan = stream->chan;
	rb_chan = consumer_chan->chan->priv->rb_chan;
	if (rb_chan->backend.config.output != RING_BUFFER_MMAP)
		return -EINVAL;
	mmap_buf_len = rb_chan->backend.buf_size;
	if (rb_chan->backend.extra_reader_sb)
		mmap_buf_len += rb_chan->backend.subbuf_size;
	if (mmap_buf_len > INT_MAX)
		return -EFBIG;
	*len = mmap_buf_len;
	return 0;
}

/* returns the maximum size for sub-buffers. */
int lttng_ust_ctl_get_max_subbuf_size(struct lttng_ust_ctl_consumer_stream *stream,
		unsigned long *len)
{
	struct lttng_ust_ctl_consumer_channel *consumer_chan;
	struct lttng_ust_ring_buffer_channel *rb_chan;

	if (!stream)
		return -EINVAL;
	consumer_chan = stream->chan;
	rb_chan = consumer_chan->chan->priv->rb_chan;
	*len = rb_chan->backend.subbuf_size;
	return 0;
}

/*
 * For mmap mode, operate on the current packet (between get/put or
 * get_next/put_next).
 */

/* returns the offset of the subbuffer belonging to the mmap reader. */
int lttng_ust_ctl_get_mmap_read_offset(struct lttng_ust_ctl_consumer_stream *stream,
		unsigned long *off)
{
	struct lttng_ust_ring_buffer_channel *rb_chan;
	unsigned long sb_bindex;
	struct lttng_ust_ring_buffer *buf;
	struct lttng_ust_ctl_consumer_channel *consumer_chan;
	struct lttng_ust_ring_buffer_backend_pages_shmp *barray_idx;
	struct lttng_ust_ring_buffer_backend_pages *pages;
	struct lttng_ust_sigbus_range range;
	int ret;

	if (!stream)
		return -EINVAL;
	buf = stream->buf;
	consumer_chan = stream->chan;
	rb_chan = consumer_chan->chan->priv->rb_chan;
	if (rb_chan->backend.config.output != RING_BUFFER_MMAP)
		return -EINVAL;

	if (sigbus_begin())
		return -EIO;
	ret = 0;
	lttng_ust_sigbus_add_range(&range, stream->memory_map_addr,
				stream->memory_map_size);

	sb_bindex = subbuffer_id_get_index(&rb_chan->backend.config,
					buf->backend.buf_rsb.id);
	barray_idx = shmp_index(rb_chan->handle, buf->backend.array,
			sb_bindex);
	if (!barray_idx) {
		ret = -EINVAL;
		goto end;
	}
	pages = shmp(rb_chan->handle, barray_idx->shmp);
	if (!pages) {
		ret = -EINVAL;
		goto end;
	}
	*off = pages->mmap_offset;
end:
	lttng_ust_sigbus_del_range(&range);
	sigbus_end();
	return ret;
}

/* returns the size of the current sub-buffer, without padding (for mmap). */
int lttng_ust_ctl_get_subbuf_size(struct lttng_ust_ctl_consumer_stream *stream,
		unsigned long *len)
{
	struct lttng_ust_ctl_consumer_channel *consumer_chan;
	struct lttng_ust_ring_buffer_channel *rb_chan;
	struct lttng_ust_ring_buffer *buf;
	struct lttng_ust_sigbus_range range;

	if (!stream)
		return -EINVAL;

	buf = stream->buf;
	consumer_chan = stream->chan;
	rb_chan = consumer_chan->chan->priv->rb_chan;
	if (sigbus_begin())
		return -EIO;
	lttng_ust_sigbus_add_range(&range, stream->memory_map_addr,
				stream->memory_map_size);
	*len = lib_ring_buffer_get_read_data_size(&rb_chan->backend.config, buf,
		rb_chan->handle);
	lttng_ust_sigbus_del_range(&range);
	sigbus_end();
	return 0;
}

/* returns the size of the current sub-buffer, without padding (for mmap). */
int lttng_ust_ctl_get_padded_subbuf_size(struct lttng_ust_ctl_consumer_stream *stream,
		unsigned long *len)
{
	struct lttng_ust_ctl_consumer_channel *consumer_chan;
	struct lttng_ust_ring_buffer_channel *rb_chan;
	struct lttng_ust_ring_buffer *buf;
	struct lttng_ust_sigbus_range range;

	if (!stream)
		return -EINVAL;
	buf = stream->buf;
	consumer_chan = stream->chan;
	rb_chan = consumer_chan->chan->priv->rb_chan;
	if (sigbus_begin())
		return -EIO;
	lttng_ust_sigbus_add_range(&range, stream->memory_map_addr,
				stream->memory_map_size);
	*len = lib_ring_buffer_get_read_data_size(&rb_chan->backend.config, buf,
		rb_chan->handle);
	*len = LTTNG_UST_PAGE_ALIGN(*len);
	lttng_ust_sigbus_del_range(&range);
	sigbus_end();
	return 0;
}

/* Get exclusive read access to the next sub-buffer that can be read. */
int lttng_ust_ctl_get_next_subbuf(struct lttng_ust_ctl_consumer_stream *stream)
{
	struct lttng_ust_ring_buffer *buf;
	struct lttng_ust_ctl_consumer_channel *consumer_chan;
	struct lttng_ust_sigbus_range range;
	int ret;

	if (!stream)
		return -EINVAL;
	buf = stream->buf;
	consumer_chan = stream->chan;
	if (sigbus_begin())
		return -EIO;
	lttng_ust_sigbus_add_range(&range, stream->memory_map_addr,
				stream->memory_map_size);
	ret = lib_ring_buffer_get_next_subbuf(buf,
			consumer_chan->chan->priv->rb_chan->handle);
	lttng_ust_sigbus_del_range(&range);
	sigbus_end();
	return ret;
}

/* Release exclusive sub-buffer access, move consumer forward. */
int lttng_ust_ctl_put_next_subbuf(struct lttng_ust_ctl_consumer_stream *stream)
{
	struct lttng_ust_ring_buffer *buf;
	struct lttng_ust_ctl_consumer_channel *consumer_chan;
	struct lttng_ust_sigbus_range range;

	if (!stream)
		return -EINVAL;
	buf = stream->buf;
	consumer_chan = stream->chan;
	if (sigbus_begin())
		return -EIO;
	lttng_ust_sigbus_add_range(&range, stream->memory_map_addr,
				stream->memory_map_size);
	lib_ring_buffer_put_next_subbuf(buf, consumer_chan->chan->priv->rb_chan->handle);
	lttng_ust_sigbus_del_range(&range);
	sigbus_end();
	return 0;
}

/* snapshot */

/* Get a snapshot of the current ring buffer producer and consumer positions */
int lttng_ust_ctl_snapshot(struct lttng_ust_ctl_consumer_stream *stream)
{
	struct lttng_ust_ring_buffer *buf;
	struct lttng_ust_ctl_consumer_channel *consumer_chan;
	struct lttng_ust_sigbus_range range;
	int ret;

	if (!stream)
		return -EINVAL;
	buf = stream->buf;
	consumer_chan = stream->chan;
	if (sigbus_begin())
		return -EIO;
	lttng_ust_sigbus_add_range(&range, stream->memory_map_addr,
				stream->memory_map_size);
	ret = lib_ring_buffer_snapshot(buf, &buf->cons_snapshot,
			&buf->prod_snapshot, consumer_chan->chan->priv->rb_chan->handle);
	lttng_ust_sigbus_del_range(&range);
	sigbus_end();
	return ret;
}

/*
 * Get a snapshot of the current ring buffer producer and consumer positions
 * even if the consumed and produced positions are contained within the same
 * subbuffer.
 */
int lttng_ust_ctl_snapshot_sample_positions(struct lttng_ust_ctl_consumer_stream *stream)
{
	struct lttng_ust_ring_buffer *buf;
	struct lttng_ust_ctl_consumer_channel *consumer_chan;
	struct lttng_ust_sigbus_range range;
	int ret;

	if (!stream)
		return -EINVAL;
	buf = stream->buf;
	consumer_chan = stream->chan;
	if (sigbus_begin())
		return -EIO;
	lttng_ust_sigbus_add_range(&range, stream->memory_map_addr,
				stream->memory_map_size);
	ret = lib_ring_buffer_snapshot_sample_positions(buf,
			&buf->cons_snapshot, &buf->prod_snapshot,
			consumer_chan->chan->priv->rb_chan->handle);
	lttng_ust_sigbus_del_range(&range);
	sigbus_end();
	return ret;
}

/* Get the consumer position (iteration start) */
int lttng_ust_ctl_snapshot_get_consumed(struct lttng_ust_ctl_consumer_stream *stream,
		unsigned long *pos)
{
	struct lttng_ust_ring_buffer *buf;

	if (!stream)
		return -EINVAL;
	buf = stream->buf;
	*pos = buf->cons_snapshot;
	return 0;
}

/* Get the producer position (iteration end) */
int lttng_ust_ctl_snapshot_get_produced(struct lttng_ust_ctl_consumer_stream *stream,
		unsigned long *pos)
{
	struct lttng_ust_ring_buffer *buf;

	if (!stream)
		return -EINVAL;
	buf = stream->buf;
	*pos = buf->prod_snapshot;
	return 0;
}

/* Get exclusive read access to the specified sub-buffer position */
int lttng_ust_ctl_get_subbuf(struct lttng_ust_ctl_consumer_stream *stream,
		unsigned long *pos)
{
	struct lttng_ust_ring_buffer *buf;
	struct lttng_ust_ctl_consumer_channel *consumer_chan;
	struct lttng_ust_sigbus_range range;
	int ret;

	if (!stream)
		return -EINVAL;
	buf = stream->buf;
	consumer_chan = stream->chan;
	if (sigbus_begin())
		return -EIO;
	lttng_ust_sigbus_add_range(&range, stream->memory_map_addr,
				stream->memory_map_size);
	ret = lib_ring_buffer_get_subbuf(buf, *pos,
			consumer_chan->chan->priv->rb_chan->handle);
	lttng_ust_sigbus_del_range(&range);
	sigbus_end();
	return ret;
}

/* Release exclusive sub-buffer access */
int lttng_ust_ctl_put_subbuf(struct lttng_ust_ctl_consumer_stream *stream)
{
	struct lttng_ust_ring_buffer *buf;
	struct lttng_ust_ctl_consumer_channel *consumer_chan;
	struct lttng_ust_sigbus_range range;

	if (!stream)
		return -EINVAL;
	buf = stream->buf;
	consumer_chan = stream->chan;
	if (sigbus_begin())
		return -EIO;
	lttng_ust_sigbus_add_range(&range, stream->memory_map_addr,
				stream->memory_map_size);
	lib_ring_buffer_put_subbuf(buf, consumer_chan->chan->priv->rb_chan->handle);
	lttng_ust_sigbus_del_range(&range);
	sigbus_end();
	return 0;
}

int lttng_ust_ctl_flush_buffer(struct lttng_ust_ctl_consumer_stream *stream,
		int producer_active)
{
	struct lttng_ust_ring_buffer *buf;
	struct lttng_ust_ctl_consumer_channel *consumer_chan;
	struct lttng_ust_sigbus_range range;

	assert(stream);
	buf = stream->buf;
	consumer_chan = stream->chan;
	if (sigbus_begin())
		return -EIO;
	lttng_ust_sigbus_add_range(&range, stream->memory_map_addr,
				stream->memory_map_size);
	lib_ring_buffer_switch_slow(buf,
		producer_active ? SWITCH_ACTIVE : SWITCH_FLUSH,
		consumer_chan->chan->priv->rb_chan->handle);
	lttng_ust_sigbus_del_range(&range);
	sigbus_end();
	return 0;
}

int lttng_ust_ctl_clear_buffer(struct lttng_ust_ctl_consumer_stream *stream)
{
	struct lttng_ust_ring_buffer *buf;
	struct lttng_ust_ctl_consumer_channel *consumer_chan;
	struct lttng_ust_sigbus_range range;

	assert(stream);
	buf = stream->buf;
	consumer_chan = stream->chan;
	if (sigbus_begin())
		return -EIO;
	lttng_ust_sigbus_add_range(&range, stream->memory_map_addr,
				stream->memory_map_size);
	lib_ring_buffer_switch_slow(buf, SWITCH_ACTIVE,
		consumer_chan->chan->priv->rb_chan->handle);
	lib_ring_buffer_clear_reader(buf, consumer_chan->chan->priv->rb_chan->handle);
	lttng_ust_sigbus_del_range(&range);
	sigbus_end();
	return 0;
}

static
struct lttng_ust_client_lib_ring_buffer_client_cb *get_client_cb(
		struct lttng_ust_ring_buffer *buf __attribute__((unused)),
		struct lttng_ust_ring_buffer_channel *chan)
{
	const struct lttng_ust_ring_buffer_config *config;
	struct lttng_ust_client_lib_ring_buffer_client_cb *client_cb;

	config = &chan->backend.config;
	if (!config->cb_ptr)
		return NULL;
	client_cb = caa_container_of(config->cb_ptr,
			struct lttng_ust_client_lib_ring_buffer_client_cb,
			parent);
	return client_cb;
}

int lttng_ust_ctl_get_timestamp_begin(struct lttng_ust_ctl_consumer_stream *stream,
		uint64_t *timestamp_begin)
{
	struct lttng_ust_client_lib_ring_buffer_client_cb *client_cb;
	struct lttng_ust_ring_buffer_channel *chan;
	struct lttng_ust_ring_buffer *buf;
	struct lttng_ust_sigbus_range range;
	int ret;

	if (!stream || !timestamp_begin)
		return -EINVAL;
	buf = stream->buf;
	chan = stream->chan->chan->priv->rb_chan;
	client_cb = get_client_cb(buf, chan);
	if (!client_cb)
		return -ENOSYS;
	if (sigbus_begin())
		return -EIO;
	lttng_ust_sigbus_add_range(&range, stream->memory_map_addr,
				stream->memory_map_size);
	ret = client_cb->timestamp_begin(buf, chan, timestamp_begin);
	lttng_ust_sigbus_del_range(&range);
	sigbus_end();
	return ret;
}

int lttng_ust_ctl_get_timestamp_end(struct lttng_ust_ctl_consumer_stream *stream,
	uint64_t *timestamp_end)
{
	struct lttng_ust_client_lib_ring_buffer_client_cb *client_cb;
	struct lttng_ust_ring_buffer_channel *chan;
	struct lttng_ust_ring_buffer *buf;
	struct lttng_ust_sigbus_range range;
	int ret;

	if (!stream || !timestamp_end)
		return -EINVAL;
	buf = stream->buf;
	chan = stream->chan->chan->priv->rb_chan;
	client_cb = get_client_cb(buf, chan);
	if (!client_cb)
		return -ENOSYS;
	if (sigbus_begin())
		return -EIO;
	lttng_ust_sigbus_add_range(&range, stream->memory_map_addr,
				stream->memory_map_size);
	ret = client_cb->timestamp_end(buf, chan, timestamp_end);
	lttng_ust_sigbus_del_range(&range);
	sigbus_end();
	return ret;
}

int lttng_ust_ctl_get_events_discarded(struct lttng_ust_ctl_consumer_stream *stream,
	uint64_t *events_discarded)
{
	struct lttng_ust_client_lib_ring_buffer_client_cb *client_cb;
	struct lttng_ust_ring_buffer_channel *chan;
	struct lttng_ust_ring_buffer *buf;
	struct lttng_ust_sigbus_range range;
	int ret;

	if (!stream || !events_discarded)
		return -EINVAL;
	buf = stream->buf;
	chan = stream->chan->chan->priv->rb_chan;
	client_cb = get_client_cb(buf, chan);
	if (!client_cb)
		return -ENOSYS;
	if (sigbus_begin())
		return -EIO;
	lttng_ust_sigbus_add_range(&range, stream->memory_map_addr,
				stream->memory_map_size);
	ret = client_cb->events_discarded(buf, chan, events_discarded);
	lttng_ust_sigbus_del_range(&range);
	sigbus_end();
	return ret;
}

int lttng_ust_ctl_get_content_size(struct lttng_ust_ctl_consumer_stream *stream,
	uint64_t *content_size)
{
	struct lttng_ust_client_lib_ring_buffer_client_cb *client_cb;
	struct lttng_ust_ring_buffer_channel *chan;
	struct lttng_ust_ring_buffer *buf;
	struct lttng_ust_sigbus_range range;
	int ret;

	if (!stream || !content_size)
		return -EINVAL;
	buf = stream->buf;
	chan = stream->chan->chan->priv->rb_chan;
	client_cb = get_client_cb(buf, chan);
	if (!client_cb)
		return -ENOSYS;
	if (sigbus_begin())
		return -EIO;
	lttng_ust_sigbus_add_range(&range, stream->memory_map_addr,
				stream->memory_map_size);
	ret = client_cb->content_size(buf, chan, content_size);
	lttng_ust_sigbus_del_range(&range);
	sigbus_end();
	return ret;
}

int lttng_ust_ctl_get_packet_size(struct lttng_ust_ctl_consumer_stream *stream,
	uint64_t *packet_size)
{
	struct lttng_ust_client_lib_ring_buffer_client_cb *client_cb;
	struct lttng_ust_ring_buffer_channel *chan;
	struct lttng_ust_ring_buffer *buf;
	struct lttng_ust_sigbus_range range;
	int ret;

	if (!stream || !packet_size)
		return -EINVAL;
	buf = stream->buf;
	chan = stream->chan->chan->priv->rb_chan;
	client_cb = get_client_cb(buf, chan);
	if (!client_cb)
		return -ENOSYS;
	if (sigbus_begin())
		return -EIO;
	lttng_ust_sigbus_add_range(&range, stream->memory_map_addr,
				stream->memory_map_size);
	ret = client_cb->packet_size(buf, chan, packet_size);
	lttng_ust_sigbus_del_range(&range);
	sigbus_end();
	return ret;
}

int lttng_ust_ctl_get_stream_id(struct lttng_ust_ctl_consumer_stream *stream,
		uint64_t *stream_id)
{
	struct lttng_ust_client_lib_ring_buffer_client_cb *client_cb;
	struct lttng_ust_ring_buffer_channel *chan;
	struct lttng_ust_ring_buffer *buf;
	struct lttng_ust_sigbus_range range;
	int ret;

	if (!stream || !stream_id)
		return -EINVAL;
	buf = stream->buf;
	chan = stream->chan->chan->priv->rb_chan;
	client_cb = get_client_cb(buf, chan);
	if (!client_cb)
		return -ENOSYS;
	if (sigbus_begin())
		return -EIO;
	lttng_ust_sigbus_add_range(&range, stream->memory_map_addr,
				stream->memory_map_size);
	ret = client_cb->stream_id(buf, chan, stream_id);
	lttng_ust_sigbus_del_range(&range);
	sigbus_end();
	return ret;
}

int lttng_ust_ctl_get_current_timestamp(struct lttng_ust_ctl_consumer_stream *stream,
		uint64_t *ts)
{
	struct lttng_ust_client_lib_ring_buffer_client_cb *client_cb;
	struct lttng_ust_ring_buffer_channel *chan;
	struct lttng_ust_ring_buffer *buf;
	struct lttng_ust_sigbus_range range;
	int ret;

	if (!stream || !ts)
		return -EINVAL;
	buf = stream->buf;
	chan = stream->chan->chan->priv->rb_chan;
	client_cb = get_client_cb(buf, chan);
	if (!client_cb || !client_cb->current_timestamp)
		return -ENOSYS;
	if (sigbus_begin())
		return -EIO;
	lttng_ust_sigbus_add_range(&range, stream->memory_map_addr,
				stream->memory_map_size);
	ret = client_cb->current_timestamp(buf, chan, ts);
	lttng_ust_sigbus_del_range(&range);
	sigbus_end();
	return ret;
}

int lttng_ust_ctl_get_sequence_number(struct lttng_ust_ctl_consumer_stream *stream,
		uint64_t *seq)
{
	struct lttng_ust_client_lib_ring_buffer_client_cb *client_cb;
	struct lttng_ust_ring_buffer_channel *chan;
	struct lttng_ust_ring_buffer *buf;
	struct lttng_ust_sigbus_range range;
	int ret;

	if (!stream || !seq)
		return -EINVAL;
	buf = stream->buf;
	chan = stream->chan->chan->priv->rb_chan;
	client_cb = get_client_cb(buf, chan);
	if (!client_cb || !client_cb->sequence_number)
		return -ENOSYS;
	if (sigbus_begin())
		return -EIO;
	lttng_ust_sigbus_add_range(&range, stream->memory_map_addr,
				stream->memory_map_size);
	ret = client_cb->sequence_number(buf, chan, seq);
	lttng_ust_sigbus_del_range(&range);
	sigbus_end();
	return ret;
}

int lttng_ust_ctl_get_instance_id(struct lttng_ust_ctl_consumer_stream *stream,
		uint64_t *id)
{
	struct lttng_ust_client_lib_ring_buffer_client_cb *client_cb;
	struct lttng_ust_ring_buffer_channel *chan;
	struct lttng_ust_ring_buffer *buf;
	struct lttng_ust_sigbus_range range;
	int ret;

	if (!stream || !id)
		return -EINVAL;
	buf = stream->buf;
	chan = stream->chan->chan->priv->rb_chan;
	client_cb = get_client_cb(buf, chan);
	if (!client_cb)
		return -ENOSYS;
	if (sigbus_begin())
		return -EIO;
	lttng_ust_sigbus_add_range(&range, stream->memory_map_addr,
				stream->memory_map_size);
	ret = client_cb->instance_id(buf, chan, id);
	lttng_ust_sigbus_del_range(&range);
	sigbus_end();
	return ret;
}

#ifdef HAVE_LINUX_PERF_EVENT_H

int lttng_ust_ctl_has_perf_counters(void)
{
	return 1;
}

#else

int lttng_ust_ctl_has_perf_counters(void)
{
	return 0;
}

#endif

#ifdef __linux__
/*
 * Override application pid/uid/gid with unix socket credentials. If
 * the application announced a pid matching our view, it means it is
 * within the same pid namespace, so expose the ppid provided by the
 * application.
 */
static
int get_cred(int sock,
	const struct lttng_ust_ctl_reg_msg *reg_msg,
	uint32_t *pid,
	uint32_t *ppid,
	uint32_t *uid,
	uint32_t *gid)
{
	struct ucred ucred;
	socklen_t ucred_len = sizeof(struct ucred);
	int ret;

	ret = getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &ucred, &ucred_len);
	if (ret) {
		return -LTTNG_UST_ERR_PEERCRED;
	}
	DBG("Unix socket peercred [ pid: %u, uid: %u, gid: %u ], "
		"application registered claiming [ pid: %u, ppid: %u, uid: %u, gid: %u ]",
		ucred.pid, ucred.uid, ucred.gid,
		reg_msg->pid, reg_msg->ppid, reg_msg->uid, reg_msg->gid);
	if (!ucred.pid) {
		ERR("Unix socket credential pid=0. Refusing application in distinct, non-nested pid namespace.");
		return -LTTNG_UST_ERR_PEERCRED_PID;
	}
	*pid = ucred.pid;
	*uid = ucred.uid;
	*gid = ucred.gid;
	if (ucred.pid == reg_msg->pid) {
		*ppid = reg_msg->ppid;
	} else {
		*ppid = 0;
	}
	return 0;
}
#elif defined(__FreeBSD__)
#include <sys/ucred.h>
#include <sys/un.h>

/*
 * Override application uid/gid with unix socket credentials. Use the
 * first group of the cr_groups.
 */
static
int get_cred(int sock,
	const struct lttng_ust_ctl_reg_msg *reg_msg,
	uint32_t *pid,
	uint32_t *ppid,
	uint32_t *uid,
	uint32_t *gid)
{
	struct xucred xucred;
	socklen_t xucred_len = sizeof(struct xucred);
	int ret;

	ret = getsockopt(sock, SOL_LOCAL, LOCAL_PEERCRED, &xucred, &xucred_len);
	if (ret) {
		return -LTTNG_UST_ERR_PEERCRED;
	}
	if (xucred.cr_version != XUCRED_VERSION || xucred.cr_ngroups < 1) {
		return -LTTNG_UST_ERR_PEERCRED;
	}
	DBG("Unix socket peercred [ pid: %u, uid: %u, gid: %u ], "
		"application registered claiming [ pid: %u, ppid: %u, uid: %u, gid: %u ]",
		xucred.cr_pid, xucred.cr_uid, xucred.cr_groups[0],
		reg_msg->pid, reg_msg->ppid, reg_msg->uid, reg_msg->gid);
	*pid = xucred.cr_pid;
	*uid = xucred.cr_uid;
	*gid = xucred.cr_groups[0];
	if (xucred.cr_pid == reg_msg->pid) {
		*ppid = reg_msg->ppid;
	} else {
		*ppid = 0;
	}
	return 0;
}
#else
#warning "Using insecure fallback: trusting user id provided by registered applications. Please consider implementing use of unix socket credentials on your platform."
static
int get_cred(int sock,
	const struct lttng_ust_ctl_reg_msg *reg_msg,
	uint32_t *pid,
	uint32_t *ppid,
	uint32_t *uid,
	uint32_t *gid)
{
	DBG("Application registered claiming [ pid: %u, ppid: %d, uid: %u, gid: %u ]",
		reg_msg->pid, reg_msg->ppid, reg_msg->uid, reg_msg->gid);
	*pid = reg_msg->pid;
	*ppid = reg_msg->ppid;
	*uid = reg_msg->uid;
	*gid = reg_msg->gid;
	return 0;
}
#endif

/*
 * Returns 0 on success, negative error value on error.
 */
int lttng_ust_ctl_recv_reg_msg(int sock,
	enum lttng_ust_ctl_socket_type *type,
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
	struct lttng_ust_ctl_reg_msg reg_msg;

	len = ustcomm_recv_unix_sock(sock, &reg_msg, sizeof(reg_msg));
	if (len > 0 && len != sizeof(reg_msg))
		return -EIO;
	if (len == 0)
		return -EPIPE;
	if (len < 0)
		return len;

	if (reg_msg.magic == LTTNG_UST_ABI_COMM_MAGIC) {
		*byte_order = LTTNG_UST_BYTE_ORDER == LTTNG_UST_BIG_ENDIAN ?
				LTTNG_UST_BIG_ENDIAN : LTTNG_UST_LITTLE_ENDIAN;
	} else if (reg_msg.magic == lttng_ust_bswap_32(LTTNG_UST_ABI_COMM_MAGIC)) {
		*byte_order = LTTNG_UST_BYTE_ORDER == LTTNG_UST_BIG_ENDIAN ?
				LTTNG_UST_LITTLE_ENDIAN : LTTNG_UST_BIG_ENDIAN;
	} else {
		return -LTTNG_UST_ERR_INVAL_MAGIC;
	}
	switch (reg_msg.socket_type) {
	case 0:	*type = LTTNG_UST_CTL_SOCKET_CMD;
		break;
	case 1:	*type = LTTNG_UST_CTL_SOCKET_NOTIFY;
		break;
	default:
		return -LTTNG_UST_ERR_INVAL_SOCKET_TYPE;
	}
	*major = reg_msg.major;
	*minor = reg_msg.minor;
	*bits_per_long = reg_msg.bits_per_long;
	*uint8_t_alignment = reg_msg.uint8_t_alignment;
	*uint16_t_alignment = reg_msg.uint16_t_alignment;
	*uint32_t_alignment = reg_msg.uint32_t_alignment;
	*uint64_t_alignment = reg_msg.uint64_t_alignment;
	*long_alignment = reg_msg.long_alignment;
	memcpy(name, reg_msg.name, LTTNG_UST_ABI_PROCNAME_LEN);
	if (reg_msg.major < LTTNG_UST_ABI_MAJOR_VERSION_OLDEST_COMPATIBLE ||
			reg_msg.major > LTTNG_UST_ABI_MAJOR_VERSION) {
		return -LTTNG_UST_ERR_UNSUP_MAJOR;
	}
	return get_cred(sock, &reg_msg, pid, ppid, uid, gid);
}

int lttng_ust_ctl_recv_notify(int sock, enum lttng_ust_ctl_notify_cmd *notify_cmd)
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
		*notify_cmd = LTTNG_UST_CTL_NOTIFY_CMD_EVENT;
		break;
	case 1:
		*notify_cmd = LTTNG_UST_CTL_NOTIFY_CMD_CHANNEL;
		break;
	case 2:
		*notify_cmd = LTTNG_UST_CTL_NOTIFY_CMD_ENUM;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

/*
 * Returns 0 on success, negative error value on error.
 */
int lttng_ust_ctl_recv_register_event(int sock,
	int *session_objd,
	int *channel_objd,
	char *event_name,
	int *loglevel,
	char **signature,
	size_t *nr_fields,
	struct lttng_ust_ctl_field **fields,
	char **model_emf_uri)
{
	ssize_t len;
	struct ustcomm_notify_event_msg msg;
	size_t signature_len, fields_len, model_emf_uri_len;
	char *a_sign = NULL, *a_model_emf_uri = NULL;
	struct lttng_ust_ctl_field *a_fields = NULL;

	len = ustcomm_recv_unix_sock(sock, &msg, sizeof(msg));
	if (len > 0 && len != sizeof(msg))
		return -EIO;
	if (len == 0)
		return -EPIPE;
	if (len < 0)
		return len;

	*session_objd = msg.session_objd;
	*channel_objd = msg.channel_objd;
	strncpy(event_name, msg.event_name, LTTNG_UST_ABI_SYM_NAME_LEN);
	event_name[LTTNG_UST_ABI_SYM_NAME_LEN - 1] = '\0';
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
int lttng_ust_ctl_reply_register_event(int sock,
	uint32_t id,
	int ret_code)
{
	ssize_t len;
	struct {
		struct ustcomm_notify_hdr header;
		struct ustcomm_notify_event_reply r;
	} reply;

	memset(&reply, 0, sizeof(reply));
	reply.header.notify_cmd = LTTNG_UST_CTL_NOTIFY_CMD_EVENT;
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
int lttng_ust_ctl_recv_register_enum(int sock,
	int *session_objd,
	char *enum_name,
	struct lttng_ust_ctl_enum_entry **entries,
	size_t *nr_entries)
{
	ssize_t len;
	struct ustcomm_notify_enum_msg msg;
	size_t entries_len;
	struct lttng_ust_ctl_enum_entry *a_entries = NULL;

	len = ustcomm_recv_unix_sock(sock, &msg, sizeof(msg));
	if (len > 0 && len != sizeof(msg))
		return -EIO;
	if (len == 0)
		return -EPIPE;
	if (len < 0)
		return len;

	*session_objd = msg.session_objd;
	strncpy(enum_name, msg.enum_name, LTTNG_UST_ABI_SYM_NAME_LEN);
	enum_name[LTTNG_UST_ABI_SYM_NAME_LEN - 1] = '\0';
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
int lttng_ust_ctl_reply_register_enum(int sock,
	uint64_t id,
	int ret_code)
{
	ssize_t len;
	struct {
		struct ustcomm_notify_hdr header;
		struct ustcomm_notify_enum_reply r;
	} reply;

	memset(&reply, 0, sizeof(reply));
	reply.header.notify_cmd = LTTNG_UST_CTL_NOTIFY_CMD_ENUM;
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
int lttng_ust_ctl_recv_register_channel(int sock,
	int *session_objd,		/* session descriptor (output) */
	int *channel_objd,		/* channel descriptor (output) */
	size_t *nr_fields,
	struct lttng_ust_ctl_field **fields)
{
	ssize_t len;
	struct ustcomm_notify_channel_msg msg;
	size_t fields_len;
	struct lttng_ust_ctl_field *a_fields;

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
int lttng_ust_ctl_reply_register_channel(int sock,
	uint32_t chan_id,
	enum lttng_ust_ctl_channel_header header_type,
	int ret_code)
{
	ssize_t len;
	struct {
		struct ustcomm_notify_hdr header;
		struct ustcomm_notify_channel_reply r;
	} reply;

	memset(&reply, 0, sizeof(reply));
	reply.header.notify_cmd = LTTNG_UST_CTL_NOTIFY_CMD_CHANNEL;
	reply.r.ret_code = ret_code;
	reply.r.chan_id = chan_id;
	switch (header_type) {
	case LTTNG_UST_CTL_CHANNEL_HEADER_COMPACT:
		reply.r.header_type = 1;
		break;
	case LTTNG_UST_CTL_CHANNEL_HEADER_LARGE:
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

/* Regenerate the statedump. */
int lttng_ust_ctl_regenerate_statedump(int sock, int handle)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret;

	memset(&lum, 0, sizeof(lum));
	lum.handle = handle;
	lum.cmd = LTTNG_UST_ABI_SESSION_STATEDUMP;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	DBG("Regenerated statedump for handle %u", handle);
	return 0;
}

/* counter operations */

int lttng_ust_ctl_get_nr_cpu_per_counter(void)
{
	return num_possible_cpus();
}

struct lttng_ust_ctl_daemon_counter *
	lttng_ust_ctl_create_counter(size_t nr_dimensions,
		const struct lttng_ust_ctl_counter_dimension *dimensions,
		int64_t global_sum_step,
		int global_counter_fd,
		int nr_counter_cpu_fds,
		const int *counter_cpu_fds,
		enum lttng_ust_ctl_counter_bitness bitness,
		enum lttng_ust_ctl_counter_arithmetic arithmetic,
		uint32_t alloc_flags,
		bool coalesce_hits)
{
	const char *transport_name;
	struct lttng_ust_ctl_daemon_counter *counter;
	struct lttng_counter_transport *transport;
	struct lttng_counter_dimension ust_dim[LTTNG_COUNTER_DIMENSION_MAX];
	size_t i;

	if (nr_dimensions > LTTNG_COUNTER_DIMENSION_MAX)
		return NULL;
	/* Currently, only per-cpu allocation is supported. */
	switch (alloc_flags) {
	case LTTNG_UST_CTL_COUNTER_ALLOC_PER_CPU:
		break;

	case LTTNG_UST_CTL_COUNTER_ALLOC_PER_CPU | LTTNG_UST_CTL_COUNTER_ALLOC_GLOBAL:
	case LTTNG_UST_CTL_COUNTER_ALLOC_GLOBAL:
	default:
		return NULL;
	}
	switch (bitness) {
	case LTTNG_UST_CTL_COUNTER_BITNESS_32:
		switch (arithmetic) {
		case LTTNG_UST_CTL_COUNTER_ARITHMETIC_MODULAR:
			transport_name = "counter-per-cpu-32-modular";
			break;
		case LTTNG_UST_CTL_COUNTER_ARITHMETIC_SATURATION:
			transport_name = "counter-per-cpu-32-saturation";
			break;
		default:
			return NULL;
		}
		break;
	case LTTNG_UST_CTL_COUNTER_BITNESS_64:
		switch (arithmetic) {
		case LTTNG_UST_CTL_COUNTER_ARITHMETIC_MODULAR:
			transport_name = "counter-per-cpu-64-modular";
			break;
		case LTTNG_UST_CTL_COUNTER_ARITHMETIC_SATURATION:
			transport_name = "counter-per-cpu-64-saturation";
			break;
		default:
			return NULL;
		}
		break;
	default:
		return NULL;
	}

	transport = lttng_counter_transport_find(transport_name);
	if (!transport) {
		DBG("LTTng transport %s not found\n",
			transport_name);
		return NULL;
	}

	counter = zmalloc(sizeof(*counter));
	if (!counter)
		return NULL;
	counter->attr = zmalloc(sizeof(*counter->attr));
	if (!counter->attr)
		goto free_counter;
	counter->attr->bitness = bitness;
	counter->attr->arithmetic = arithmetic;
	counter->attr->nr_dimensions = nr_dimensions;
	counter->attr->global_sum_step = global_sum_step;
	counter->attr->coalesce_hits = coalesce_hits;
	for (i = 0; i < nr_dimensions; i++)
		counter->attr->dimensions[i] = dimensions[i];

	for (i = 0; i < nr_dimensions; i++) {
		ust_dim[i].size = dimensions[i].size;
		ust_dim[i].underflow_index = dimensions[i].underflow_index;
		ust_dim[i].overflow_index = dimensions[i].overflow_index;
		ust_dim[i].has_underflow = dimensions[i].has_underflow;
		ust_dim[i].has_overflow = dimensions[i].has_overflow;
	}
	counter->counter = transport->ops.counter_create(nr_dimensions,
		ust_dim, global_sum_step, global_counter_fd,
		nr_counter_cpu_fds, counter_cpu_fds, true);
	if (!counter->counter)
		goto free_attr;
	counter->ops = &transport->ops;
	return counter;

free_attr:
	free(counter->attr);
free_counter:
	free(counter);
	return NULL;
}

int lttng_ust_ctl_create_counter_data(struct lttng_ust_ctl_daemon_counter *counter,
		struct lttng_ust_abi_object_data **_counter_data)
{
	struct lttng_ust_abi_object_data *counter_data;
	struct lttng_ust_abi_counter_conf counter_conf = {0};
	size_t i;
	int ret;

	switch (counter->attr->arithmetic) {
	case LTTNG_UST_CTL_COUNTER_ARITHMETIC_MODULAR:
		counter_conf.arithmetic = LTTNG_UST_ABI_COUNTER_ARITHMETIC_MODULAR;
		break;
	case LTTNG_UST_CTL_COUNTER_ARITHMETIC_SATURATION:
		counter_conf.arithmetic = LTTNG_UST_ABI_COUNTER_ARITHMETIC_SATURATION;
		break;
	default:
		return -EINVAL;
	}
	switch (counter->attr->bitness) {
	case LTTNG_UST_CTL_COUNTER_BITNESS_32:
		counter_conf.bitness = LTTNG_UST_ABI_COUNTER_BITNESS_32;
		break;
	case LTTNG_UST_CTL_COUNTER_BITNESS_64:
		counter_conf.bitness = LTTNG_UST_ABI_COUNTER_BITNESS_64;
		break;
	default:
		return -EINVAL;
	}
	counter_conf.number_dimensions = counter->attr->nr_dimensions;
	counter_conf.global_sum_step = counter->attr->global_sum_step;
	counter_conf.coalesce_hits = counter->attr->coalesce_hits;
	for (i = 0; i < counter->attr->nr_dimensions; i++) {
		counter_conf.dimensions[i].size = counter->attr->dimensions[i].size;
		counter_conf.dimensions[i].underflow_index = counter->attr->dimensions[i].underflow_index;
		counter_conf.dimensions[i].overflow_index = counter->attr->dimensions[i].overflow_index;
		counter_conf.dimensions[i].has_underflow = counter->attr->dimensions[i].has_underflow;
		counter_conf.dimensions[i].has_overflow = counter->attr->dimensions[i].has_overflow;
	}

	counter_data = zmalloc(sizeof(*counter_data));
	if (!counter_data) {
		ret = -ENOMEM;
		goto error_alloc;
	}
	counter_data->type = LTTNG_UST_ABI_OBJECT_TYPE_COUNTER;
	counter_data->handle = -1;

	counter_data->size = sizeof(counter_conf);
	counter_data->u.counter.data = zmalloc(sizeof(counter_conf));
	if (!counter_data->u.counter.data) {
		ret = -ENOMEM;
		goto error_alloc_data;
	}

	memcpy(counter_data->u.counter.data, &counter_conf, sizeof(counter_conf));
	*_counter_data = counter_data;

	return 0;

error_alloc_data:
	free(counter_data);
error_alloc:
	return ret;
}

int lttng_ust_ctl_create_counter_global_data(struct lttng_ust_ctl_daemon_counter *counter,
		struct lttng_ust_abi_object_data **_counter_global_data)
{
	struct lttng_ust_abi_object_data *counter_global_data;
	int ret, fd;
	size_t len;

	if (lttng_counter_get_global_shm(counter->counter, &fd, &len))
		return -EINVAL;
	counter_global_data = zmalloc(sizeof(*counter_global_data));
	if (!counter_global_data) {
		ret = -ENOMEM;
		goto error_alloc;
	}
	counter_global_data->type = LTTNG_UST_ABI_OBJECT_TYPE_COUNTER_GLOBAL;
	counter_global_data->handle = -1;
	counter_global_data->size = len;
	counter_global_data->u.counter_global.shm_fd = fd;
	*_counter_global_data = counter_global_data;
	return 0;

error_alloc:
	return ret;
}

int lttng_ust_ctl_create_counter_cpu_data(struct lttng_ust_ctl_daemon_counter *counter, int cpu,
		struct lttng_ust_abi_object_data **_counter_cpu_data)
{
	struct lttng_ust_abi_object_data *counter_cpu_data;
	int ret, fd;
	size_t len;

	if (lttng_counter_get_cpu_shm(counter->counter, cpu, &fd, &len))
		return -EINVAL;
	counter_cpu_data = zmalloc(sizeof(*counter_cpu_data));
	if (!counter_cpu_data) {
		ret = -ENOMEM;
		goto error_alloc;
	}
	counter_cpu_data->type = LTTNG_UST_ABI_OBJECT_TYPE_COUNTER_CPU;
	counter_cpu_data->handle = -1;
	counter_cpu_data->size = len;
	counter_cpu_data->u.counter_cpu.shm_fd = fd;
	counter_cpu_data->u.counter_cpu.cpu_nr = cpu;
	*_counter_cpu_data = counter_cpu_data;
	return 0;

error_alloc:
	return ret;
}

void lttng_ust_ctl_destroy_counter(struct lttng_ust_ctl_daemon_counter *counter)
{
	counter->ops->counter_destroy(counter->counter);
	free(counter->attr);
	free(counter);
}

/*
 * Protocol for LTTNG_UST_ABI_COUNTER command:
 *
 * - send:     struct ustcomm_ust_msg
 * - receive:  struct ustcomm_ust_reply
 * - send:     counter data
 * - receive:  struct ustcomm_ust_reply (actual command return code)
 */
int lttng_ust_ctl_send_counter_data_to_ust(int sock, int parent_handle,
		struct lttng_ust_abi_object_data *counter_data)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret;
	size_t size;
	ssize_t len;

	if (!counter_data)
		return -EINVAL;

	size = counter_data->size;
	memset(&lum, 0, sizeof(lum));
	lum.handle = parent_handle;
	lum.cmd = LTTNG_UST_ABI_COUNTER;
	lum.u.counter.len = size;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;

	/* Send counter data */
	len = ustcomm_send_unix_sock(sock, counter_data->u.counter.data, size);
	if (len != size) {
		if (len < 0)
			return len;
		else
			return -EIO;
	}

	ret = ustcomm_recv_app_reply(sock, &lur, lum.handle, lum.cmd);
	if (!ret) {
		counter_data->handle = lur.ret_val;
	}
	return ret;
}

/*
 * Protocol for LTTNG_UST_ABI_COUNTER_GLOBAL command:
 *
 * - send:     struct ustcomm_ust_msg
 * - receive:  struct ustcomm_ust_reply
 * - send:     file descriptor
 * - receive:  struct ustcomm_ust_reply (actual command return code)
 */
int lttng_ust_ctl_send_counter_global_data_to_ust(int sock,
		struct lttng_ust_abi_object_data *counter_data,
		struct lttng_ust_abi_object_data *counter_global_data)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret, shm_fd[1];
	size_t size;
	ssize_t len;

	if (!counter_data || !counter_global_data)
		return -EINVAL;

	size = counter_global_data->size;
	memset(&lum, 0, sizeof(lum));
	lum.handle = counter_data->handle;	/* parent handle */
	lum.cmd = LTTNG_UST_ABI_COUNTER_GLOBAL;
	lum.u.counter_global.len = size;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;

	shm_fd[0] = counter_global_data->u.counter_global.shm_fd;
	len = ustcomm_send_fds_unix_sock(sock, shm_fd, 1);
	if (len <= 0) {
		if (len < 0)
			return len;
		else
			return -EIO;
	}

	ret = ustcomm_recv_app_reply(sock, &lur, lum.handle, lum.cmd);
	if (!ret) {
		counter_global_data->handle = lur.ret_val;
	}
	return ret;
}

/*
 * Protocol for LTTNG_UST_ABI_COUNTER_CPU command:
 *
 * - send:     struct ustcomm_ust_msg
 * - receive:  struct ustcomm_ust_reply
 * - send:     file descriptor
 * - receive:  struct ustcomm_ust_reply (actual command return code)
 */
int lttng_ust_ctl_send_counter_cpu_data_to_ust(int sock,
		struct lttng_ust_abi_object_data *counter_data,
		struct lttng_ust_abi_object_data *counter_cpu_data)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret, shm_fd[1];
	size_t size;
	ssize_t len;

	if (!counter_data || !counter_cpu_data)
		return -EINVAL;

	size = counter_cpu_data->size;
	memset(&lum, 0, sizeof(lum));
	lum.handle = counter_data->handle;	/* parent handle */
	lum.cmd = LTTNG_UST_ABI_COUNTER_CPU;
	lum.u.counter_cpu.len = size;
	lum.u.counter_cpu.cpu_nr = counter_cpu_data->u.counter_cpu.cpu_nr;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;

	shm_fd[0] = counter_cpu_data->u.counter_global.shm_fd;
	len = ustcomm_send_fds_unix_sock(sock, shm_fd, 1);
	if (len <= 0) {
		if (len < 0)
			return len;
		else
			return -EIO;
	}

	ret = ustcomm_recv_app_reply(sock, &lur, lum.handle, lum.cmd);
	if (!ret) {
		counter_cpu_data->handle = lur.ret_val;
	}
	return ret;
}

int lttng_ust_ctl_counter_read(struct lttng_ust_ctl_daemon_counter *counter,
		const size_t *dimension_indexes,
		int cpu, int64_t *value,
		bool *overflow, bool *underflow)
{
	return counter->ops->counter_read(counter->counter, dimension_indexes, cpu,
			value, overflow, underflow);
}

int lttng_ust_ctl_counter_aggregate(struct lttng_ust_ctl_daemon_counter *counter,
		const size_t *dimension_indexes,
		int64_t *value,
		bool *overflow, bool *underflow)
{
	return counter->ops->counter_aggregate(counter->counter, dimension_indexes,
			value, overflow, underflow);
}

int lttng_ust_ctl_counter_clear(struct lttng_ust_ctl_daemon_counter *counter,
		const size_t *dimension_indexes)
{
	return counter->ops->counter_clear(counter->counter, dimension_indexes);
}

static
void lttng_ust_ctl_ctor(void)
	__attribute__((constructor));
static
void lttng_ust_ctl_ctor(void)
{
	/*
	 * Call the liblttng-ust-common constructor to ensure it runs first.
	 */
	lttng_ust_common_ctor();

	lttng_ust_ring_buffer_clients_init();
	lttng_ust_counter_clients_init();
	lib_ringbuffer_signal_init();
}

static
void lttng_ust_ctl_exit(void)
	__attribute__((destructor));
static
void lttng_ust_ctl_exit(void)
{
	lttng_ust_counter_clients_exit();
	lttng_ust_ring_buffer_clients_exit();
}
