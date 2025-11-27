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

#include "common/clock.h"
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

#define DEFINE_ZEROED(type, name)		\
	type name;				\
	memset(&name, '\0', sizeof(type))

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
	uint64_t clock_freq;
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

/*
 * Packet representation
 */
struct lttng_ust_ctl_consumer_packet {
	uint64_t packet_length;
	uint64_t packet_length_padded;
	void *p;
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
	struct lttng_ust_channel_counter *counter;
	const struct lttng_ust_channel_counter_ops *ops;
	struct lttng_ust_ctl_counter_attr *attr;	/* initial attributes */
};

/*
 * Evaluates to false if transaction begins, true if it has failed due to SIGBUS.
 * The entire transaction must complete before the current function returns.
 * A transaction can contain 0 or more tracked ranges as sigbus begin/end pairs.
 */
#define sigbus_begin() \
({ \
	bool _ret; \
	\
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
		_ret = true; \
	} else { \
		cmm_barrier(); \
		CMM_STORE_SHARED(lttng_ust_sigbus_state.jmp_ready, 1); \
		_ret = false; \
	} \
	_ret; \
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
	DEFINE_ZEROED(struct ustcomm_ust_msg_header, lum);
	DEFINE_ZEROED(struct ustcomm_ust_reply, lur);

	if (sock < 0 || handle < 0)
		return 0;
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

	switch (data->header.type) {
	case LTTNG_UST_ABI_OBJECT_TYPE_CHANNEL:
		if (data->type.channel.wakeup_fd >= 0) {
			ret = close(data->type.channel.wakeup_fd);
			if (ret < 0) {
				ret = -errno;
				return ret;
			}
			data->type.channel.wakeup_fd = -1;
		}
		free(data->type.channel.data);
		data->type.channel.data = NULL;
		break;
	case LTTNG_UST_ABI_OBJECT_TYPE_STREAM:
		if (data->type.stream.shm_fd >= 0) {
			ret = close(data->type.stream.shm_fd);
			if (ret < 0) {
				ret = -errno;
				return ret;
			}
			data->type.stream.shm_fd = -1;
		}
		if (data->type.stream.wakeup_fd >= 0) {
			ret = close(data->type.stream.wakeup_fd);
			if (ret < 0) {
				ret = -errno;
				return ret;
			}
			data->type.stream.wakeup_fd = -1;
		}
		break;
	case LTTNG_UST_ABI_OBJECT_TYPE_EVENT:
	case LTTNG_UST_ABI_OBJECT_TYPE_CONTEXT:
	case LTTNG_UST_ABI_OBJECT_TYPE_EVENT_NOTIFIER_GROUP:
	case LTTNG_UST_ABI_OBJECT_TYPE_EVENT_NOTIFIER:
	case LTTNG_UST_ABI_OBJECT_TYPE_COUNTER_EVENT:
		break;
	case LTTNG_UST_ABI_OBJECT_TYPE_COUNTER:
		free(data->type.counter.data);
		data->type.counter.data = NULL;
		break;
	case LTTNG_UST_ABI_OBJECT_TYPE_COUNTER_CHANNEL:
		if (data->type.counter_channel.shm_fd >= 0) {
			ret = close(data->type.counter_channel.shm_fd);
			if (ret < 0) {
				ret = -errno;
				return ret;
			}
			data->type.counter_channel.shm_fd = -1;
		}
		break;
	case LTTNG_UST_ABI_OBJECT_TYPE_COUNTER_CPU:
		if (data->type.counter_cpu.shm_fd >= 0) {
			ret = close(data->type.counter_cpu.shm_fd);
			if (ret < 0) {
				ret = -errno;
				return ret;
			}
			data->type.counter_cpu.shm_fd = -1;
		}
		break;
	default:
		assert(0);
	}
	return lttng_ust_ctl_release_handle(sock, data->header.handle);
}

/*
 * Send registration done packet to the application.
 */
int lttng_ust_ctl_register_done(int sock)
{
	DEFINE_ZEROED(struct ustcomm_ust_msg_header, lum);
	DEFINE_ZEROED(struct ustcomm_ust_reply, lur);
	int ret;

	DBG("Sending register done command to %d", sock);
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
	DEFINE_ZEROED(struct ustcomm_ust_msg_header, lum);
	DEFINE_ZEROED(struct ustcomm_ust_reply, lur);
	int ret, session_handle;

	/* Create session */
	lum.handle = LTTNG_UST_ABI_ROOT_HANDLE;
	lum.cmd = LTTNG_UST_ABI_SESSION;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	session_handle = lur.header.ret_val;
	DBG("received session handle %u", session_handle);
	return session_handle;
}

int lttng_ust_ctl_create_event(int sock, struct lttng_ust_abi_event *ev,
		struct lttng_ust_abi_object_data *channel_data,
		struct lttng_ust_abi_object_data **_event_data)
{
	DEFINE_ZEROED(struct ustcomm_ust_msg_header, lum);
	DEFINE_ZEROED(struct ustcomm_ust_reply, lur);
	DEFINE_ZEROED(struct lttng_ust_abi_event, ev_copy);
	struct iovec iov[] = {
		{
			.iov_base = &ev_copy,
			.iov_len = sizeof(ev_copy),
		},
	};
	int ret;
	struct lttng_ust_abi_object_data *event_data;

	if (!channel_data || !_event_data)
		return -EINVAL;

	event_data = zmalloc(sizeof(*event_data));
	if (!event_data)
		return -ENOMEM;

	ev_copy.instrumentation = ev->instrumentation;
	ev_copy.loglevel_type = ev->loglevel_type;
	ev_copy.loglevel = ev->loglevel;
	ev_copy.token = ev->token;
	memcpy(ev_copy.name, ev->name, sizeof(ev_copy.name));

	event_data->header.type = LTTNG_UST_ABI_OBJECT_TYPE_EVENT;
	lum.handle = channel_data->header.handle;
	lum.cmd = LTTNG_UST_ABI_EVENT;

	ret = ustcomm_send_app_msg(sock, &lum,
				iov, LTTNG_ARRAY_SIZE(iov),
				NULL, 0);
	if (ret < 0) {
		free(event_data);
		return ret;
	}

	ret = ustcomm_recv_app_reply(sock, &lur, lum.handle, lum.cmd);
	if (ret < 0) {
		free(event_data);
		return ret;
	}

	event_data->header.handle = lur.header.ret_val;
	DBG("received event handle %u", event_data->header.handle);
	*_event_data = event_data;
	return 0;
}

/*
 * Protocol for LTTNG_UST_ABI_CONTEXT command:
 *
 * - send:     struct ustcomm_ust_msg_header
 * - send:     var len ctx_name
 * - receive:  struct ustcomm_ust_reply
 */
int lttng_ust_ctl_add_context(int sock, struct lttng_ust_context_attr *ctx,
		struct lttng_ust_abi_object_data *obj_data,
		struct lttng_ust_abi_object_data **_context_data)
{
	DEFINE_ZEROED(struct ustcomm_ust_msg_header, lum);
	DEFINE_ZEROED(struct ustcomm_ust_reply, lur);
	DEFINE_ZEROED(struct lttng_ust_abi_context, context);
	char buf[LTTNG_UST_ABI_SYM_NAME_LEN] = {0};
	struct iovec iov[] = {
		{
			.iov_base = &context,
			.iov_len = sizeof(context),
		},
		{
			.iov_base = buf,
			.iov_len = 0,
		},
	};
	int ret;
	struct lttng_ust_abi_object_data *context_data = NULL;
	size_t len;

	if (!obj_data || !_context_data) {
		ret = -EINVAL;
		goto end;
	}

	context_data = zmalloc(sizeof(*context_data));
	if (!context_data) {
		ret = -ENOMEM;
		goto end;
	}

	context_data->header.type = LTTNG_UST_ABI_OBJECT_TYPE_CONTEXT;
	lum.handle = obj_data->header.handle;
	lum.cmd = LTTNG_UST_ABI_CONTEXT;
	context.header.ctx = ctx->ctx;
	switch (ctx->ctx) {
	case LTTNG_UST_ABI_CONTEXT_PERF_THREAD_COUNTER:
		context.type.perf_counter = ctx->u.perf_counter;
		break;
	case LTTNG_UST_ABI_CONTEXT_APP_CONTEXT:
	{
		size_t provider_name_len = strlen(ctx->u.app_ctx.provider_name);
		size_t ctx_name_len = strlen(ctx->u.app_ctx.ctx_name);

		context.type.app_ctx.provider_name_len = provider_name_len;
		context.type.app_ctx.ctx_name_len = ctx_name_len;

		len = provider_name_len + ctx_name_len;

		/* Never filled entirely for null byte. */
		if (len >= sizeof(buf)) {
			ret = -E2BIG;
			goto end;
		}

		memcpy(buf,
			ctx->u.app_ctx.provider_name,
			provider_name_len);

		memcpy(buf + provider_name_len,
			ctx->u.app_ctx.ctx_name,
			ctx_name_len);

		iov[1].iov_len = len;
		break;
	}
	default:
		break;
	}
	ret = ustcomm_send_app_msg(sock, &lum,
				iov, LTTNG_ARRAY_SIZE(iov),
				NULL, 0);
	if (ret < 0)
		goto end;

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
	context_data->header.handle = -1;
	DBG("Context created successfully");
	*_context_data = context_data;
	context_data = NULL;
end:
	free(context_data);

	return ret;
}

/*
 * Protocol for LTTNG_UST_ABI_FILTER command:
 *
 * - send:     struct ustcomm_ust_msg_header
 * - send:     var len bytecode
 * - receive:  struct ustcomm_ust_reply
 */
int lttng_ust_ctl_set_filter(int sock, struct lttng_ust_abi_filter_bytecode *bytecode,
		struct lttng_ust_abi_object_data *obj_data)
{
	DEFINE_ZEROED(struct ustcomm_ust_msg_header, lum);
	DEFINE_ZEROED(struct ustcomm_ust_reply, lur);
	DEFINE_ZEROED(struct lttng_ust_abi_filter_bytecode, filter);
	struct iovec iov[] = {
		{
			.iov_base = &filter,
			.iov_len = sizeof(filter)
		},
		{
			.iov_base = bytecode->data,
			.iov_len = bytecode->len,
		}
	};
	int ret;

	if (!obj_data)
		return -EINVAL;

	lum.handle = obj_data->header.handle;
	lum.cmd = LTTNG_UST_ABI_FILTER;

	filter.len = bytecode->len;
	filter.reloc_offset = bytecode->reloc_offset;
	filter.seqnum = bytecode->seqnum;

	ret = ustcomm_send_app_msg(sock, &lum,
				iov, LTTNG_ARRAY_SIZE(iov),
				NULL, 0);
	if (ret < 0)
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

/*
 * Protocol for LTTNG_UST_ABI_CAPTURE command:
 *
 * - send:     struct ustcomm_ust_msg_header
 * - send:     var len bytecode
 * - receive:  struct ustcomm_ust_reply (actual command return code)
 */
int lttng_ust_ctl_set_capture(int sock, struct lttng_ust_abi_capture_bytecode *bytecode,
		struct lttng_ust_abi_object_data *obj_data)
{
	DEFINE_ZEROED(struct ustcomm_ust_msg_header, lum);
	DEFINE_ZEROED(struct ustcomm_ust_reply, lur);
	DEFINE_ZEROED(struct lttng_ust_abi_capture_bytecode, capture);
	struct iovec iov[] = {
		{
			.iov_base = &capture,
			.iov_len = sizeof(capture),
		},
		{
			.iov_base = bytecode->data,
			.iov_len = bytecode->len,
		},
	};
	int ret;

	if (!obj_data)
		return -EINVAL;

	capture.len = bytecode->len;
	capture.reloc_offset = bytecode->reloc_offset;
	capture.seqnum = bytecode->seqnum;

	lum.handle = obj_data->header.handle;
	lum.cmd = LTTNG_UST_ABI_CAPTURE;

	ret = ustcomm_send_app_msg(sock, &lum,
				iov, LTTNG_ARRAY_SIZE(iov),
				NULL, 0);

	if (ret < 0) {
		return ret;
	}

	return ustcomm_recv_app_reply(sock, &lur, lum.handle, lum.cmd);
}

/*
 * Protocol for LTTNG_UST_ABI_EXCLUSION command:
 *
 * - send:     struct ustcomm_ust_msg_header
 * - send:     var len exclusion names
 * - receive:  struct ustcomm_ust_reply
 */
int lttng_ust_ctl_set_exclusion(int sock, struct lttng_ust_abi_event_exclusion *exclusion,
		struct lttng_ust_abi_object_data *obj_data)
{
	DEFINE_ZEROED(struct ustcomm_ust_msg_header, lum);
	DEFINE_ZEROED(struct ustcomm_ust_reply, lur);
	struct iovec iov[] = {
		{
			.iov_base = exclusion,
			.iov_len = sizeof(*exclusion),
		},
		{
			.iov_base = exclusion->names,
			.iov_len = exclusion->count * LTTNG_UST_ABI_SYM_NAME_LEN,
		},
	};
	int ret;

	if (!obj_data) {
		return -EINVAL;
	}

	lum.handle = obj_data->header.handle;
	lum.cmd = LTTNG_UST_ABI_EXCLUSION;

	ret = ustcomm_send_app_msg(sock, &lum,
				iov, LTTNG_ARRAY_SIZE(iov),
				NULL, 0);
	if (ret< 0) {
		return ret;
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
	DEFINE_ZEROED(struct ustcomm_ust_msg_header, lum);
	DEFINE_ZEROED(struct ustcomm_ust_reply, lur);
	int ret;

	if (!object)
		return -EINVAL;

	lum.handle = object->header.handle;
	lum.cmd = LTTNG_UST_ABI_ENABLE;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	DBG("enabled handle %u", object->header.handle);
	return 0;
}

/* Disable event, channel and session ioctl */
int lttng_ust_ctl_disable(int sock, struct lttng_ust_abi_object_data *object)
{
	DEFINE_ZEROED(struct ustcomm_ust_msg_header, lum);
	DEFINE_ZEROED(struct ustcomm_ust_reply, lur);
	int ret;

	if (!object)
		return -EINVAL;

	lum.handle = object->header.handle;
	lum.cmd = LTTNG_UST_ABI_DISABLE;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	DBG("disable handle %u", object->header.handle);
	return 0;
}

int lttng_ust_ctl_start_session(int sock, int handle)
{
	struct lttng_ust_abi_object_data obj;

	obj.header.handle = handle;
	return lttng_ust_ctl_enable(sock, &obj);
}

int lttng_ust_ctl_stop_session(int sock, int handle)
{
	struct lttng_ust_abi_object_data obj;

	obj.header.handle = handle;
	return lttng_ust_ctl_disable(sock, &obj);
}

/*
 * Protocol for LTTNG_UST_ABI_EVENT_NOTIFIER_GROUP_CREATE command:
 *
 * - send:     struct ustcomm_ust_msg_header
 * - send:     file descriptor
 * - receive:  struct ustcomm_ust_reply (actual command return code)
 */
int lttng_ust_ctl_create_event_notifier_group(int sock, int pipe_fd,
		struct lttng_ust_abi_object_data **_event_notifier_group_data)
{
	DEFINE_ZEROED(struct ustcomm_ust_msg_header, lum);
	DEFINE_ZEROED(struct ustcomm_ust_reply, lur);
	char dummy = '\0';
	struct iovec iov[] = {
		{
			.iov_base = &dummy,
			.iov_len = sizeof(dummy),
		}
	};
	int ret;
	struct lttng_ust_abi_object_data *event_notifier_group_data;
	int fds[] = {
		pipe_fd,
	};

	if (!_event_notifier_group_data)
		return -EINVAL;

	event_notifier_group_data = zmalloc(sizeof(*event_notifier_group_data));
	if (!event_notifier_group_data)
		return -ENOMEM;

	event_notifier_group_data->header.type = LTTNG_UST_ABI_OBJECT_TYPE_EVENT_NOTIFIER_GROUP;

	lum.handle = LTTNG_UST_ABI_ROOT_HANDLE;
	lum.cmd = LTTNG_UST_ABI_EVENT_NOTIFIER_GROUP_CREATE;
	ret = ustcomm_send_app_msg(sock, &lum,
				iov, LTTNG_ARRAY_SIZE(iov),
				fds, LTTNG_ARRAY_SIZE(fds));

	if (ret < 0)
		goto error;

	ret = ustcomm_recv_app_reply(sock, &lur, lum.handle, lum.cmd);
	if (ret)
		goto error;

	event_notifier_group_data->header.handle = lur.header.ret_val;
	DBG("received event_notifier group handle %d", event_notifier_group_data->header.handle);

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
 * - send:     struct ustcomm_ust_msg_header
 * - send:     struct lttng_ust_abi_event_notifier
 * - receive:  struct ustcomm_ust_reply (actual command return code)
 */
int lttng_ust_ctl_create_event_notifier(int sock, struct lttng_ust_abi_event_notifier *event_notifier,
		struct lttng_ust_abi_object_data *event_notifier_group,
		struct lttng_ust_abi_object_data **_event_notifier_data)
{
	DEFINE_ZEROED(struct ustcomm_ust_msg_header, lum);
	DEFINE_ZEROED(struct ustcomm_ust_reply, lur);
	struct iovec iov[] = {
		{
			.iov_base = event_notifier,
			.iov_len = sizeof(*event_notifier),
		},
	};
	int ret;
	struct lttng_ust_abi_object_data *event_notifier_data;

	if (!event_notifier_group || !_event_notifier_data)
		return -EINVAL;

	event_notifier_data = zmalloc(sizeof(*event_notifier_data));
	if (!event_notifier_data)
		return -ENOMEM;

	event_notifier_data->header.type = LTTNG_UST_ABI_OBJECT_TYPE_EVENT_NOTIFIER;

	lum.handle = event_notifier_group->header.handle;
	lum.cmd = LTTNG_UST_ABI_EVENT_NOTIFIER_CREATE;

	ret = ustcomm_send_app_msg(sock, &lum,
				iov, LTTNG_ARRAY_SIZE(iov),
				NULL, 0);
	if (ret < 0) {
		free(event_notifier_data);
		return ret;
	}

	ret = ustcomm_recv_app_reply(sock, &lur, lum.handle, lum.cmd);
	if (ret) {
		free(event_notifier_data);
		return ret;
	}
	event_notifier_data->header.handle = lur.header.ret_val;
	DBG("received event_notifier handle %u", event_notifier_data->header.handle);
	*_event_notifier_data = event_notifier_data;

	return ret;
}

int lttng_ust_ctl_tracepoint_list(int sock)
{
	DEFINE_ZEROED(struct ustcomm_ust_msg_header, lum);
	DEFINE_ZEROED(struct ustcomm_ust_reply, lur);
	int ret, tp_list_handle;

	lum.handle = LTTNG_UST_ABI_ROOT_HANDLE;
	lum.cmd = LTTNG_UST_ABI_TRACEPOINT_LIST;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	tp_list_handle = lur.header.ret_val;
	DBG("received tracepoint list handle %u", tp_list_handle);
	return tp_list_handle;
}

int lttng_ust_ctl_tracepoint_list_get(int sock, int tp_list_handle,
		struct lttng_ust_abi_tracepoint_iter *iter)
{
	DEFINE_ZEROED(struct ustcomm_ust_msg_header, lum);
	DEFINE_ZEROED(struct ustcomm_ust_reply, lur);
	int ret;

	if (!iter)
		return -EINVAL;

	lum.handle = tp_list_handle;
	lum.cmd = LTTNG_UST_ABI_TRACEPOINT_LIST_GET;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	DBG("received tracepoint list entry name %s loglevel %d",
		lur.cmd.tracepoint.name,
		lur.cmd.tracepoint.loglevel);
	memcpy(iter, &lur.cmd.tracepoint, sizeof(*iter));
	return 0;
}

int lttng_ust_ctl_tracepoint_field_list(int sock)
{
	DEFINE_ZEROED(struct ustcomm_ust_msg_header, lum);
	DEFINE_ZEROED(struct ustcomm_ust_reply, lur);
	int ret, tp_field_list_handle;

	lum.handle = LTTNG_UST_ABI_ROOT_HANDLE;
	lum.cmd = LTTNG_UST_ABI_TRACEPOINT_FIELD_LIST;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	tp_field_list_handle = lur.header.ret_val;
	DBG("received tracepoint field list handle %u", tp_field_list_handle);
	return tp_field_list_handle;
}

int lttng_ust_ctl_tracepoint_field_list_get(int sock, int tp_field_list_handle,
		struct lttng_ust_abi_field_iter *iter)
{
	DEFINE_ZEROED(struct ustcomm_ust_msg_header, lum);
	DEFINE_ZEROED(struct ustcomm_ust_reply, lur);
	int ret;
	ssize_t len;

	if (!iter)
		return -EINVAL;

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
	DEFINE_ZEROED(struct ustcomm_ust_msg_header, lum);
	DEFINE_ZEROED(struct ustcomm_ust_reply, lur);
	int ret;

	if (!v)
		return -EINVAL;

	lum.handle = LTTNG_UST_ABI_ROOT_HANDLE;
	lum.cmd = LTTNG_UST_ABI_TRACER_VERSION;

	ret = ustcomm_send_app_msg(sock, &lum,
				NULL, 0,
				NULL, 0);

	if (ret < 0)
		return ret;

	ret = ustcomm_recv_app_reply(sock, &lur, lum.handle, lum.cmd);

	if (ret == 0) {
		memcpy(v, &lur.cmd.version, sizeof(*v));
		DBG("received tracer version");
	}

	return ret;
}

/*
 * The unknown command is meant to be used for testing only. Users should never
 * use that command.
 *
 * The command will return 0 if all internal tests pass.
 *
 * The following tests are done:
 *
 *   1. A dummy payload is sent with the read end of a socket pair before being
 *   closed.
 *
 *   2. The client replied with `LTTNG_UST_ERR_NOSYS`
 *
 *   3. The command writes to the write end of the pipe and expect `errno` to be
 *   `EPIPE`.
 *
 * The tests validate that the client will correctly handle unknown command by
 * returning the appropriate error code and close any sent file descriptor.
 */
int lttng_ust_ctl_unknown_command(int sock)
{
	DEFINE_ZEROED(struct ustcomm_ust_msg_header, lum);
	DEFINE_ZEROED(struct ustcomm_ust_reply, lur);
	char buf[27] = {0};
	struct iovec iov[] = {
		{
			.iov_base = buf,
			.iov_len = LTTNG_ARRAY_SIZE(buf),
		},
	};
	int ret;
	char dummy = '\0';
	int fds[2];

	/*
	 * Note that passing SOCK_CLOEXEC | SOCK_NONBLOCK flags to `type' is a
	 * Linux extension.
	 */
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, fds) < 0)
		return -errno;

	lum.cmd = LTTNG_UST_ABI_UNKNOWN_COMMAND;

	ret = ustcomm_send_app_msg(sock, &lum,
				iov, LTTNG_ARRAY_SIZE(iov),
				&fds[0], 1);

	(void) close(fds[0]);

	/* Error while sending message. This command does not check for that. */
	if (ret < 0) {
		ret = 0;
		goto out;
	}

	ret = ustcomm_recv_app_reply(sock, &lur, lum.handle, lum.cmd);

	switch (ret) {
	case -LTTNG_UST_ERR_NOSYS:
		break;
	case -EPIPE:		/* Maybe the application died. */
		ret = 0;
		/* fall through */
	default:
		goto out;
	}

	ret = send(fds[1], &dummy, sizeof(dummy), MSG_NOSIGNAL);

	/*
	 * Some bytes were sent, which means the read side is still open.
	 */
	if (ret != -1) {
		/* EIO is not used by send(2). */
		ret = -EIO;
	} else if (errno == EPIPE) {
		ret = 0;
	} else {
		ret = -errno;
	}

out:
	(void) close(fds[1]);

	return ret;
}

int lttng_ust_ctl_wait_quiescent(int sock)
{
	DEFINE_ZEROED(struct ustcomm_ust_msg_header, lum);
	DEFINE_ZEROED(struct ustcomm_ust_reply, lur);
	int ret;

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
	DEFINE_ZEROED(struct ustcomm_ust_msg_header, lum);
	DEFINE_ZEROED(struct ustcomm_ust_reply, lur);
	int ret;

	if (!object)
		return -EINVAL;

	lum.handle = object->header.handle;
	lum.cmd = LTTNG_UST_ABI_FLUSH_BUFFER;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	DBG("flushed buffer handle %u", object->header.handle);
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
	channel_data->header.type = LTTNG_UST_ABI_OBJECT_TYPE_CHANNEL;
	channel_data->header.handle = -1;

	/* recv mmap size */
	len = ustcomm_recv_unix_sock(sock, &channel_data->header.size,
			sizeof(channel_data->header.size));
	if (len != sizeof(channel_data->header.size)) {
		if (len < 0)
			ret = len;
		else
			ret = -EINVAL;
		goto error;
	}

	/* recv channel type */
	len = ustcomm_recv_unix_sock(sock, &channel_data->type.channel.type,
			sizeof(channel_data->type.channel.type));
	if (len != sizeof(channel_data->type.channel.type)) {
		if (len < 0)
			ret = len;
		else
			ret = -EINVAL;
		goto error;
	}

	/* recv channel data */
	channel_data->type.channel.data = zmalloc(channel_data->header.size);
	if (!channel_data->type.channel.data) {
		ret = -ENOMEM;
		goto error;
	}
	len = ustcomm_recv_unix_sock(sock, channel_data->type.channel.data,
			channel_data->header.size);
	if (len != channel_data->header.size) {
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
	channel_data->type.channel.wakeup_fd = wakeup_fd;
	*_channel_data = channel_data;
	return 0;

error_recv_data:
	free(channel_data->type.channel.data);
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

	stream_data->header.type = LTTNG_UST_ABI_OBJECT_TYPE_STREAM;
	stream_data->header.handle = -1;

	/* recv mmap size */
	len = ustcomm_recv_unix_sock(sock, &stream_data->header.size,
			sizeof(stream_data->header.size));
	if (len != sizeof(stream_data->header.size)) {
		if (len < 0 && len >= INT_MIN)
			ret = len;
		else
			ret = -EINVAL;
		goto error;
	}
	if (stream_data->header.size == -1) {
		ret = -LTTNG_UST_ERR_NOENT;
		goto error;
	}

	/* recv stream nr */
	len = ustcomm_recv_unix_sock(sock, &stream_data->type.stream.stream_nr,
			sizeof(stream_data->type.stream.stream_nr));
	if (len != sizeof(stream_data->type.stream.stream_nr)) {
		if (len < 0 && len >= INT_MIN)
			ret = len;
		else
			ret = -EINVAL;
		goto error;
	}

	/* recv shm fd and wakeup fd */
	len = ustcomm_recv_fds_unix_sock(sock, fds, 2);
	if (len <= 0) {
		if (len < 0 && len >= INT_MIN) {
			ret = len;
			goto error;
		} else {
			ret = -EIO;
			goto error;
		}
	}
	stream_data->type.stream.shm_fd = fds[0];
	stream_data->type.stream.wakeup_fd = fds[1];
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
 * - send:     struct ustcomm_ust_msg_header
 * - send:     file descriptors and channel data
 * - receive:  struct ustcomm_ust_reply
 */
int lttng_ust_ctl_send_channel_to_ust(int sock, int session_handle,
				struct lttng_ust_abi_object_data *channel_data)
{
	DEFINE_ZEROED(struct ustcomm_ust_msg_header, lum);
	DEFINE_ZEROED(struct ustcomm_ust_reply, lur);
	DEFINE_ZEROED(struct lttng_ust_abi_channel, channel);
	struct iovec iov[] = {
		{
			.iov_base = &channel,
			.iov_len = sizeof(channel),
		},
		{
			.iov_base = channel_data->type.channel.data,
			.iov_len = channel_data->header.size,
		},

	};
	int ret;
	int fds[] = {
		channel_data->type.channel.wakeup_fd,
	};

	if (!channel_data)
		return -EINVAL;

	channel.len = channel_data->header.size;
	channel.type = channel_data->type.channel.type;
	channel.owner_id = channel_data->type.channel.owner_id;

	lum.handle = session_handle;
	lum.cmd = LTTNG_UST_ABI_CHANNEL;

	ret = ustcomm_send_app_msg(sock, &lum,
				iov, LTTNG_ARRAY_SIZE(iov),
				fds, LTTNG_ARRAY_SIZE(fds));
	if (ret < 0)
		return ret;

	ret = ustcomm_recv_app_reply(sock, &lur, lum.handle, lum.cmd);
	if (!ret) {
		channel_data->header.handle = lur.header.ret_val;
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
 * - send:     struct ustcomm_ust_msg_header
 * - send:     file descriptors
 * - receive:  struct ustcomm_ust_reply
 */
int lttng_ust_ctl_send_stream_to_ust(int sock,
		struct lttng_ust_abi_object_data *channel_data,
		struct lttng_ust_abi_object_data *stream_data)
{
	DEFINE_ZEROED(struct ustcomm_ust_msg_header, lum);
	DEFINE_ZEROED(struct ustcomm_ust_reply, lur);
	DEFINE_ZEROED(struct lttng_ust_abi_stream, stream);
	struct iovec iov[] = {
		{
			.iov_base = &stream,
			.iov_len = sizeof(stream),
		},
	};
	int ret, fds[2];

	if (!stream_data || !channel_data)
		return -EINVAL;

	fds[0] = stream_data->type.stream.shm_fd;
	fds[1] = stream_data->type.stream.wakeup_fd;
	stream.len = stream_data->header.size;
	stream.stream_nr = stream_data->type.stream.stream_nr;

	lum.handle = channel_data->header.handle;
	lum.cmd = LTTNG_UST_ABI_STREAM;

	ret = ustcomm_send_app_msg(sock, &lum,
				iov, LTTNG_ARRAY_SIZE(iov),
				fds, LTTNG_ARRAY_SIZE(fds));

	if (ret < 0)
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

	if (src->header.handle != -1) {
		ret = -EINVAL;
		goto error;
	}

	obj = zmalloc(sizeof(*obj));
	if (!obj) {
		ret = -ENOMEM;
		goto error;
	}

	obj->header.type = src->header.type;
	obj->header.handle = src->header.handle;
	obj->header.size = src->header.size;

	switch (obj->header.type) {
	case LTTNG_UST_ABI_OBJECT_TYPE_CHANNEL:
	{
		obj->type.channel.type = src->type.channel.type;
		if (src->type.channel.wakeup_fd >= 0) {
			obj->type.channel.wakeup_fd =
				dup(src->type.channel.wakeup_fd);
			if (obj->type.channel.wakeup_fd < 0) {
				ret = -errno;
				goto chan_error_wakeup_fd;
			}
		} else {
			obj->type.channel.wakeup_fd =
				src->type.channel.wakeup_fd;
		}
		obj->type.channel.data = zmalloc(obj->header.size);
		if (!obj->type.channel.data) {
			ret = -ENOMEM;
			goto chan_error_alloc;
		}
		memcpy(obj->type.channel.data, src->type.channel.data, obj->header.size);
		break;

	chan_error_alloc:
		if (src->type.channel.wakeup_fd >= 0) {
			int closeret;

			closeret = close(obj->type.channel.wakeup_fd);
			if (closeret) {
				PERROR("close");
			}
		}
	chan_error_wakeup_fd:
		goto error_type;

	}

	case LTTNG_UST_ABI_OBJECT_TYPE_STREAM:
	{
		obj->type.stream.stream_nr = src->type.stream.stream_nr;
		if (src->type.stream.wakeup_fd >= 0) {
			obj->type.stream.wakeup_fd =
				dup(src->type.stream.wakeup_fd);
			if (obj->type.stream.wakeup_fd < 0) {
				ret = -errno;
				goto stream_error_wakeup_fd;
			}
		} else {
			obj->type.stream.wakeup_fd =
				src->type.stream.wakeup_fd;
		}

		if (src->type.stream.shm_fd >= 0) {
			obj->type.stream.shm_fd =
				dup(src->type.stream.shm_fd);
			if (obj->type.stream.shm_fd < 0) {
				ret = -errno;
				goto stream_error_shm_fd;
			}
		} else {
			obj->type.stream.shm_fd =
				src->type.stream.shm_fd;
		}
		break;

	stream_error_shm_fd:
		if (src->type.stream.wakeup_fd >= 0) {
			int closeret;

			closeret = close(obj->type.stream.wakeup_fd);
			if (closeret) {
				PERROR("close");
			}
		}
	stream_error_wakeup_fd:
		goto error_type;
	}

	case LTTNG_UST_ABI_OBJECT_TYPE_COUNTER:
	{
		obj->type.counter.data = zmalloc(obj->header.size);
		if (!obj->type.counter.data) {
			ret = -ENOMEM;
			goto error_type;
		}
		memcpy(obj->type.counter.data, src->type.counter.data, obj->header.size);
		break;
	}

	case LTTNG_UST_ABI_OBJECT_TYPE_COUNTER_CHANNEL:
	{
		if (src->type.counter_channel.shm_fd >= 0) {
			obj->type.counter_channel.shm_fd =
				dup(src->type.counter_channel.shm_fd);
			if (obj->type.counter_channel.shm_fd < 0) {
				ret = -errno;
				goto error_type;
			}
		}
		break;
	}

	case LTTNG_UST_ABI_OBJECT_TYPE_COUNTER_CPU:
	{
		obj->type.counter_cpu.cpu_nr = src->type.counter_cpu.cpu_nr;
		if (src->type.counter_cpu.shm_fd >= 0) {
			obj->type.counter_cpu.shm_fd =
				dup(src->type.counter_cpu.shm_fd);
			if (obj->type.counter_cpu.shm_fd < 0) {
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
	return get_possible_cpus_array_len();
}

struct lttng_ust_ctl_consumer_channel *
	lttng_ust_ctl_create_channel(struct lttng_ust_ctl_consumer_channel_attr *attr,
		const int *stream_fds, int nr_stream_fds)
{
	struct lttng_ust_ctl_consumer_channel *chan;
	struct lttng_ust_ring_buffer_channel *rb_chan;
	const char *transport_name;
	struct lttng_transport *transport;
	uint32_t owner = attr->owner_id;

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
	case LTTNG_UST_ABI_CHAN_PER_CHANNEL:
		if (attr->output == LTTNG_UST_ABI_MMAP) {
			if (attr->overwrite) {
				if (attr->read_timer_interval == 0) {
					transport_name = "relay-overwrite-channel-mmap";
				} else {
					transport_name = "relay-overwrite-channel-rt-mmap";
				}
			} else {
				if (attr->read_timer_interval == 0) {
					transport_name = "relay-discard-channel-mmap";
				} else {
					transport_name = "relay-discard-rt-channel-mmap";
				}
			}
		} else {
			return NULL;
		}
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
			attr->blocking_timeout,
			owner,
			attr->preallocate_backing);
	if (!chan->chan) {
		goto chan_error;
	}
	chan->chan->ops = &transport->ops;
	memcpy(&chan->attr, attr, sizeof(chan->attr));
	chan->wait_fd = lttng_ust_ctl_channel_get_wait_fd(chan);
	chan->wakeup_fd = lttng_ust_ctl_channel_get_wakeup_fd(chan);
	rb_chan = chan->chan->priv->rb_chan;
	if (rb_chan && rb_chan->backend.config.cb.ring_buffer_clock_freq)
		chan->clock_freq = rb_chan->backend.config.cb.ring_buffer_clock_freq(rb_chan);
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


void lttng_ust_ctl_set_channel_owner_id(struct lttng_ust_abi_object_data *obj,
					uint32_t id)
{
	obj->type.channel.owner_id = id;
}

/*
 * Determine if COMMIT is balanced with respect to RESERVE.
 *
 * This can only hold true if COMMIT is from the same sub-buffer index of
 * subbuf_index(RESERVE, chan).
 */
static inline
bool commit_balanced(unsigned long reserve, unsigned long commit, struct lttng_ust_ring_buffer_channel *chan)
{
	return subbuf_offset(reserve, chan) == subbuf_offset(commit,chan);
}

static inline ssize_t
find_owner(uint32_t *ids, size_t length, int32_t owner_id)
{
	if (!ids)
		return -1;

	for (size_t k = 0; k < length; ++k) {
		if (ids[k] == (uint32_t)owner_id) {
			return k;
		}
	}

	return -1;
}

static
int get_next_subbuf_context(const struct lttng_ust_ring_buffer_config *config,
			struct lttng_ust_ring_buffer_channel *chan,
			struct lttng_ust_ring_buffer *buf,
			long reserve,
			struct lttng_ust_shm_handle *handle,
			struct lttng_ust_ring_buffer_ctx_private *priv)
{
	int err;
	struct lttng_ust_client_lib_ring_buffer_client_cb *client_cb;
	uint64_t events_discarded = 0;

	client_cb = caa_container_of(config->cb_ptr,
			struct lttng_ust_client_lib_ring_buffer_client_cb,
			parent);

	if (lib_ring_buffer_get_subbuf(buf, reserve, handle) != 0) {
		return -1;
	}

	err = client_cb->timestamp_begin(buf, chan, &priv->timestamp);

	if (err)
		goto put;

	/*
	 * `events_discarded_begin()' will return the aggregated counters of
	 * lost records truncated to "unsigned long". It is stored in
	 * `records_lost_full' and the other counters are set to 0,
	 * since it is going to be aggregated anyway later.
	 *
	 * This needs to be changed whenever lost records counters are split.
	 */
	err = client_cb->events_discarded_begin(buf, chan, &events_discarded);
	priv->records_lost_full = (unsigned long) events_discarded;
	priv->records_lost_wrap = 0;
	priv->records_lost_big = 0;
put:
	lib_ring_buffer_put_subbuf(buf, handle);

	return err;
}

static inline
int do_fixup_stalled_subbuf_as_owner(const struct lttng_ust_ring_buffer_config *config,
				struct lttng_ust_ring_buffer_channel *chan,
				struct lttng_ust_ring_buffer *buf,
				size_t subbuf_idx,
				struct lttng_ust_shm_handle *handle,
				struct lttng_ust_ring_buffer_ctx *ctx,
				struct commit_counters_hot *cc_hot,
				long hot)
{
	unsigned long reserve, fill_reserve, minimal_reserve;
	long fill_diff, minimal_diff;

	/* Order read of hot with respect to reserve. */
	cmm_smp_rmb();
	reserve = v_read(config, &buf->offset);

	fill_reserve = subbuf_fill_reserve(hot, subbuf_idx, chan);
	minimal_reserve = subbuf_minimum_reserve(hot, subbuf_idx, chan);

	/*
	 * When comparing the current reserve position and the fill reserve
	 * position, a number of things can be assumed, depending on:
	 *
	 *   - The sign of reserve_diff
	 *
	 *   - If the sub-buffer is the current sub-buffer with respect to the
	 *    current reserve position
	 *
	 * These assumptions are detailed below in every branch
	 */
	fill_diff = subbuf_align(reserve - 1, chan) - fill_reserve;
	minimal_diff = reserve - minimal_reserve;

	assert(0 <= (long)chan->backend.buf_size - minimal_diff);

	/* Reservation is in this sub-buffer and in this buffer turn. */
	if (fill_diff == 0) {

		/*
		 * The reserve position is exactly at the boundary between this
		 * sub-buffer and the next sub-buffer of this turn.
		 *
		 * The commit counter of this sub-buffer is not balanced.
		 *
		 * In order to fix the stall, an observable side-effect must be
		 * made while taking a timestamp to guarantee ordering.
		 */
		long old_reserve, expected_reserve;

		if (fill_reserve == reserve) {
			old_reserve = v_cmpxchg(config, &buf->offset, reserve, reserve - 1);
			expected_reserve = reserve - 1;
		} else {
			old_reserve = reserve;
			expected_reserve = reserve;
		}

		if (old_reserve != reserve) {

			/*
			 * Someone made a reservation. Take the next
			 * sub-buffer timestamp.
			 */
			int err = get_next_subbuf_context(config,
							chan, buf,
							fill_reserve,
							handle, ctx->priv);
			if (err) {
				return -1;
			}
		} else {

			/*
			 * The reservation offset moved back in time.
			 * Take a snapshot of the time and record
			 * counters, then try to move the reservation
			 * offset back in the future so that external
			 * observers can see a side effect.
			 */
			uint64_t current_timestamp = config->cb.ring_buffer_clock_read(chan);
			uint64_t current_records_lost_full = v_read(config, &buf->records_lost_full);
			uint64_t current_records_lost_wrap = v_read(config, &buf->records_lost_wrap);
			uint64_t current_records_lost_big = v_read(config, &buf->records_lost_big);

			/* Side effect observable by external producers. */
			if (expected_reserve == v_cmpxchg(config, &buf->offset, expected_reserve, fill_reserve)) {
				/* Succeed. The time has been fixed. */
				ctx->priv->timestamp = current_timestamp;
				ctx->priv->records_lost_full = current_records_lost_full;
				ctx->priv->records_lost_wrap = current_records_lost_wrap;
				ctx->priv->records_lost_big = current_records_lost_big;
			} else {
				/*
				 * Failure. Someone made a reservation. Try
				 * to take the next sub-buffer.
				 */
				int err = get_next_subbuf_context(config,
								chan, buf,
								fill_reserve,
								handle, ctx->priv);
				if (err) {
					return -1;
				}
			}

		}

		lib_ring_buffer_lazy_padding_as_owner_slow(config, chan, buf, subbuf_idx,
							handle, ctx, hot);
	} else {
		/*
		 * At this point, it is certain that the reserve position is
		 * past this sub-buffer.
		 *
		 * This is important to understand how the reserve difference
		 * works.
		 */
		if (minimal_diff <= 0) {
			/*
			 * This can only happen if the commit counter of this
			 * sub-buffer is balanced with the reservation.
			 *
			 * Since the reservation is past this sub-buffer, this
			 * mean that the commit counter is "full" and a deliver
			 * is maybe required.
			 */
			struct commit_counters_cold *cc_cold;
			long cold;

			cc_cold = shmp_index(handle, buf->commit_cold, subbuf_idx);

			cold = v_read(config, &cc_cold->cc_sb);

			/*
			 * Since the sub-buffer is full, fill_reserve will point
			 * to the next buffer. Thus, it is certain that it is at
			 * least buf_size.
			 */
			if (cold != hot) {
				/* Crash happend during deliver. */
				if (cold == (hot - chan->backend.subbuf_size) + 1) {
					v_set(config, &cc_cold->cc_sb, cold - 1);
				}
				assert(fill_reserve > chan->backend.buf_size);
				lib_ring_buffer_reserve_push_reader(config, buf, chan,
								fill_reserve - chan->backend.buf_size - 1);
				lib_ring_buffer_check_deliver_slow(config, buf, chan,
								fill_reserve - chan->backend.buf_size - 1,
								hot, subbuf_idx, handle, ctx);
			} else {
				/* Spurious wakeup */
				if (config->wakeup == RING_BUFFER_WAKEUP_BY_WRITER
					&& uatomic_read(&buf->active_readers)) {
					lib_ring_buffer_wakeup(buf, handle);
				}
			}
		} else {
			int err = get_next_subbuf_context(config,
							chan, buf,
							fill_reserve,
							handle, ctx->priv);
			if (err) {
				lib_ring_buffer_switch_slow(buf, SWITCH_ACTIVE, handle);
				return -1;
			}

			lib_ring_buffer_lazy_padding_as_owner_slow(config, chan, buf, subbuf_idx,
								handle, ctx, hot);
		}
	}

	v_set(config, &cc_hot->owner, LTTNG_UST_ABI_OWNER_ID_UNSET);

	return 0;
}

static inline
int fixup_stalled_subbuf(const struct lttng_ust_ring_buffer_config *config,
			struct lttng_ust_ring_buffer_channel *chan,
			struct lttng_ust_ring_buffer *buf,
			size_t subbuf_idx,
			struct lttng_ust_shm_handle *handle,
			uint32_t *ids,
			size_t length,
			struct lttng_ust_ring_buffer_ctx *ctx)
{
	struct commit_counters_hot *cc_hot;
	long actual_owner;
	long hot;

	cc_hot = shmp_index(handle, buf->commit_hot, subbuf_idx);

	if (!cc_hot)
		return -1;

	actual_owner = v_read(config, &cc_hot->owner);
	cmm_smp_rmb();
	hot = v_read(config, &cc_hot->cc);

	if (find_owner(ids, length, actual_owner) != -1) {

		/* Take ownership. */
		int err;

		v_set(config, &cc_hot->owner, chan->u.s.owner_id);

		/*
		 * Since ownership is taken, it's fine to do a none atomic read.
		 */
		err = do_fixup_stalled_subbuf_as_owner(config, chan, buf, subbuf_idx,
							handle, ctx, cc_hot, hot);

		/*
		 * Failed to fixup the stalled sub-buffer. We are still the
		 * owner of the sub-buffer. It's okay to restore the previous
		 * owner (since it's marked for reclaim) and try again later.
		 */
		if (err) {
			v_set(config, &cc_hot->owner, actual_owner);
		}

		return err;

	} else if (actual_owner == LTTNG_UST_ABI_OWNER_ID_UNSET) {

		long reserve;

		reserve = v_read(config, &buf->offset);
		cmm_smp_rmb();

		/*
		 * These are the same balanced (between the reserve position and
		 * the commit counters of the sub-buffer) checks made in
		 * do_fixup_stalled_subbuf_as_owner().
		 *
		 * The check are made here without taking the ownership to avoid
		 * any visible side effects for external producers until it's
		 * strictly necessary.
		 *
		 * In other words, if these checks passed, it's not necessary to
		 * do a fixup of the sub-buffer and thus the ownership does not
		 * need to be taken. However, if one of the checks failed, the
		 * ownership must be taken first and then the check must be
		 * remade.
		 */
		long fill_reserve = (((subbuf_trunc(hot, chan) >> chan->backend.subbuf_size_order) << chan->backend.buf_size_order)
				+ (subbuf_idx << chan->backend.subbuf_size_order) + chan->backend.subbuf_size);

		if (subbuf_align(reserve, chan) - fill_reserve == 0) {
			if (commit_balanced(reserve, hot, chan))
				return 0;
		} else {

			long reserve_diff = reserve - fill_reserve;

			/*
			 * This can only happen if the commit counter of this
			 * sub-buffer is balanced with the reservation.
			 *
			 * Since the reservation is past this sub-buffer, this
			 * means that the commit counter is "full".
			 */
			if (reserve_diff < 0) {
				return 0;
			}
		}

		if (v_cmpxchg(config, &cc_hot->owner, LTTNG_UST_ABI_OWNER_ID_UNSET, chan->u.s.owner_id) !=
			LTTNG_UST_ABI_OWNER_ID_UNSET) {
			return 0;
		}

		/* Re-read hot commit after taking ownership. */
		hot = v_read(config, &cc_hot->cc);

		return do_fixup_stalled_subbuf_as_owner(config, chan, buf, subbuf_idx,
							handle, ctx, cc_hot, hot);
	} else if (actual_owner == LTTNG_UST_ABI_OWNER_ID_CONSUMER) {
		/*
		 * This can happen if the sub-buffer had no owner and that the
		 * consumer failed to do a fixup for some reason. It will force
		 * any producer to emit a buffer-switch, thus unblocking the
		 * consumer on that sub-buffer.
		 */
		return do_fixup_stalled_subbuf_as_owner(config, chan, buf, subbuf_idx,
							handle, ctx, cc_hot, hot);
	}

	return 0;
}

static int do_lttng_ust_ctl_fixup_stalled_stream(struct lttng_ust_ctl_consumer_stream *stream,
						unsigned long consumed_pos,
						unsigned long produced_pos,
						uint32_t *ids,
						uint32_t length)
{
	int failed_count = 0;
	struct lttng_ust_ring_buffer *buf;
	struct lttng_ust_ring_buffer_channel *rb_chan;
	struct lttng_ust_ctl_consumer_channel *chan;
	struct lttng_ust_ring_buffer_ctx_private ctx_priv = {
		.is_fixup = 1,
	};
	struct lttng_ust_ring_buffer_ctx ctx = { 0 };

	ctx.priv = &ctx_priv;

	chan = stream->chan;
	rb_chan = chan->chan->priv->rb_chan;
	buf = stream->buf;

	while ((long) (consumed_pos - produced_pos) <= 0) {
		int err = fixup_stalled_subbuf(&rb_chan->backend.config,
					rb_chan, buf,
					subbuf_index(produced_pos, rb_chan),
					rb_chan->handle,
					ids,
					length,
					&ctx);
		if (err) {
			failed_count += 1;
		}

		produced_pos -= rb_chan->backend.subbuf_size;
	}

	return failed_count;
}

int lttng_ust_ctl_fixup_stalled_stream(struct lttng_ust_ctl_consumer_stream *stream,
				unsigned long consumed_pos,
				unsigned long produced_pos,
				uint32_t *ids,
				uint32_t length)
{
	struct lttng_ust_sigbus_range range;
	int failed_count;

	if (!stream)
		return -EINVAL;

	if ((long)(consumed_pos - produced_pos) >= 0)
		return 0;

	if (sigbus_begin())
		return -EIO;

	lttng_ust_sigbus_add_range(&range, stream->memory_map_addr,
				stream->memory_map_size);

	failed_count = do_lttng_ust_ctl_fixup_stalled_stream(stream,
							consumed_pos,
							produced_pos,
							ids, length);
	lttng_ust_sigbus_del_range(&range);

	sigbus_end();

	return failed_count;
}

struct lttng_ust_ctl_subbuf_iter {
	struct lttng_ust_ring_buffer *buf;
	struct lttng_ust_ring_buffer_channel *chan;
	enum lttng_ust_ctl_subbuf_iter_type type;
	bool valid;
	unsigned long iter_pos;
	unsigned long iter_next_pos;
	unsigned long iter_end;
	unsigned long consumed_pos;
	unsigned long produced_pos;
	unsigned long cc_hot;
	unsigned long cc_cold;
	size_t idx;
	uint32_t owner;

	/* Delivered state. */
	uint64_t timestamp_begin;
	uint64_t timestamp_end;
	bool allocated;
};

int lttng_ust_ctl_subbuf_iter_create(struct lttng_ust_ctl_consumer_stream *stream,
				enum lttng_ust_ctl_subbuf_iter_type iter_type,
				struct lttng_ust_ctl_subbuf_iter **piter)
{
	unsigned long consumed_pos, produced_pos;
	struct lttng_ust_ctl_subbuf_iter *iter;
	int ret;

	if (!stream || !piter)
		return -EINVAL;

	iter = zmalloc(sizeof(*iter));
	if (!iter)
		return -ENOMEM;

	iter->buf = stream->buf;
	iter->chan = stream->chan->chan->priv->rb_chan;

	ret = lib_ring_buffer_snapshot_sample_positions(iter->buf, &consumed_pos, &produced_pos, iter->chan->handle);
	if (ret) {
		goto error;
	}
	iter->consumed_pos = consumed_pos;
	iter->produced_pos = produced_pos;
	iter->type = iter_type;
	iter->valid = false;

	/* Beginning of iteration. */
	switch (iter->type) {
	case LTTNG_UST_CTL_SUBBUF_ITER_DELIVERED:	/* Fallthrough */
	case LTTNG_UST_CTL_SUBBUF_ITER_DELIVERED_CONSUMED:
		/* Order position snapshot before reading backend pages fields. */
		cmm_smp_rmb();
		iter->iter_next_pos = subbuf_align(produced_pos - 1, iter->chan) - iter->chan->backend.buf_size;
		break;
	case LTTNG_UST_CTL_SUBBUF_ITER_UNCONSUMED:
		iter->iter_next_pos = consumed_pos;
		break;
	default:
		ret = -EINVAL;
		goto error;
	}

	/* End of iteration. */
	switch (iter->type) {
	case LTTNG_UST_CTL_SUBBUF_ITER_DELIVERED:	/* Fallthrough */
	case LTTNG_UST_CTL_SUBBUF_ITER_UNCONSUMED:
		iter->iter_end = produced_pos;
		break;
	case LTTNG_UST_CTL_SUBBUF_ITER_DELIVERED_CONSUMED:
		iter->iter_end = consumed_pos;
		break;
	default:
		ret = -EINVAL;
		goto error;
	}

	*piter = iter;

	return 0;

error:

	free(iter);
	return ret;
}

int lttng_ust_ctl_subbuf_iter_next(struct lttng_ust_ctl_subbuf_iter *piter)
{
	struct lttng_ust_ring_buffer_backend_pages *backend_pages;
	unsigned long consumed_pos, produced_pos, prev_produced_pos;
	struct lttng_ust_ctl_subbuf_iter iter = *piter;
	struct commit_counters_hot *cc_hot;
	struct commit_counters_cold *cc_cold;
	size_t subbuf_idx;
	int ret;

	piter->valid = false;

	for (;;) {
		iter.iter_pos = iter.iter_next_pos;
		iter.iter_next_pos += iter.chan->backend.subbuf_size;

		if ((long)(iter.iter_pos - iter.iter_end) >= 0)
			return 0;	/* End of iteration. */

		subbuf_idx = subbuf_index(iter.iter_pos, iter.chan);

		backend_pages = lib_ring_buffer_index_backend_pages(&iter.buf->backend, subbuf_idx, iter.chan->handle);
		if (!backend_pages) {
			return -EIO;
		}

		cc_hot = shmp_index(iter.chan->handle, iter.buf->commit_hot, subbuf_idx);
		if (!cc_hot) {
			return -EIO;
		}

		cc_cold = shmp_index(iter.chan->handle, iter.buf->commit_cold, subbuf_idx);
		if (!cc_cold){
			return -EIO;
		}

		iter.idx = subbuf_idx;
		iter.cc_hot = v_read(&iter.chan->backend.config, &cc_hot->cc);
		iter.cc_cold = v_read(&iter.chan->backend.config, &cc_cold->cc_sb);
		iter.owner = v_read(&iter.chan->backend.config, &cc_hot->owner);

		switch (iter.type) {
		case LTTNG_UST_CTL_SUBBUF_ITER_DELIVERED:		/* Fallthrough */
		case LTTNG_UST_CTL_SUBBUF_ITER_DELIVERED_CONSUMED:
			/*
			 * Check if all commits (and deliver) associated
			 * with this position have been done.
			 */
			if ((buf_trunc(iter.iter_pos, iter.chan) >> iter.chan->backend.num_subbuf_order) - ((iter.cc_cold - iter.chan->backend.subbuf_size) & iter.chan->commit_count_mask) != 0) {
				/* Retry with the next subbuffer. */
				continue;
			}
			iter.timestamp_begin = backend_pages->timestamp_begin;
			iter.timestamp_end = backend_pages->timestamp_end;
			iter.allocated = backend_pages->allocated;

			/*
			 * After reading the backend pages fields, validate once more
			 * that they have not been overwritten.
			 */
			/* Order reading backend pages fields before position snapshot. */
			cmm_smp_rmb();
			ret = lib_ring_buffer_snapshot_sample_positions(iter.buf, &consumed_pos, &produced_pos, iter.chan->handle);
			if (ret)
				return ret;
			prev_produced_pos = subbuf_align(produced_pos - 1, iter.chan) - iter.chan->backend.buf_size;
			if ((long)(iter.iter_pos - prev_produced_pos) < 0) {
				/* Retry with the next subbuffer. */
				continue;
			}
			/*
			 * Reevaluate whether consumed position has
			 * moved concurrently.
			 */
			if (iter.type == LTTNG_UST_CTL_SUBBUF_ITER_DELIVERED_CONSUMED) {
				iter.iter_end = consumed_pos;
				if ((long)(iter.iter_pos - iter.iter_end) >= 0)
					return 0;	/* End of iteration. */
			}
			break;
		case LTTNG_UST_CTL_SUBBUF_ITER_UNCONSUMED:	/* Fallthrough */
		default:
			break;
		}
		break;
	}

	iter.valid = true;
	*piter = iter;
	return 1;	/* Valid iterator. */
}


int lttng_ust_ctl_subbuf_iter_cc_hot(struct lttng_ust_ctl_subbuf_iter *iter,
				unsigned long *cc_hot)
{
	if (!iter || !cc_hot || !iter->valid)
		return -EINVAL;

	*cc_hot = iter->cc_hot;

	return 0;
}

int lttng_ust_ctl_subbuf_iter_cc_cold(struct lttng_ust_ctl_subbuf_iter *iter,
				unsigned long *cc_cold)
{
	if (!iter || !cc_cold || !iter->valid)
		return -EINVAL;

	*cc_cold = iter->cc_cold;

	return 0;
}

int lttng_ust_ctl_subbuf_iter_index(struct lttng_ust_ctl_subbuf_iter *iter,
				size_t *idx)
{
	if (!iter || !idx || !iter->valid)
		return -EINVAL;

	*idx = iter->idx;

	return 0;
}

int lttng_ust_ctl_subbuf_iter_owner(struct lttng_ust_ctl_subbuf_iter *iter,
				uint32_t *owner)
{
	if (!iter || !owner || !iter->valid)
		return -EINVAL;

	*owner = iter->owner;

	return 0;
}

int lttng_ust_ctl_subbuf_iter_timestamp_begin(struct lttng_ust_ctl_subbuf_iter *iter,
				uint64_t *timestamp_begin)
{
	if (!iter || !timestamp_begin || !iter->valid || iter->type == LTTNG_UST_CTL_SUBBUF_ITER_UNCONSUMED)
		return -EINVAL;

	*timestamp_begin = iter->timestamp_begin;

	return 0;
}

int lttng_ust_ctl_subbuf_iter_timestamp_end(struct lttng_ust_ctl_subbuf_iter *iter,
				uint64_t *timestamp_end)
{
	if (!iter || !timestamp_end || !iter->valid || iter->type == LTTNG_UST_CTL_SUBBUF_ITER_UNCONSUMED)
		return -EINVAL;

	*timestamp_end = iter->timestamp_end;

	return 0;
}

int lttng_ust_ctl_subbuf_iter_allocated(struct lttng_ust_ctl_subbuf_iter *iter,
				bool *allocated)
{
	if (!iter || !allocated || !iter->valid || iter->type == LTTNG_UST_CTL_SUBBUF_ITER_UNCONSUMED)
		return -EINVAL;

	*allocated = iter->allocated;

	return 0;
}

int lttng_ust_ctl_subbuf_iter_pos(struct lttng_ust_ctl_subbuf_iter *iter,
				unsigned long *pos)
{
	if (!iter || !pos || !iter->valid)
		return -EINVAL;

	*pos = iter->iter_pos;

	return 0;
}

int lttng_ust_ctl_subbuf_iter_destroy(struct lttng_ust_ctl_subbuf_iter *iter)
{
	free(iter);

	return 0;
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

int lttng_ust_ctl_stream_get_backend_area(struct lttng_ust_ctl_consumer_stream *stream,
		void **addr, unsigned long *len)
{
	if (!stream || !addr || !len)
		return -EINVAL;
	*addr = stream->memory_map_addr;
	*len = (unsigned long) stream->memory_map_size;
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
	ssize_t page_size;

	if (!stream)
		return -EINVAL;
	page_size = LTTNG_UST_PAGE_SIZE;
	if (page_size < 0)
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
	*len = LTTNG_UST_ALIGN(*len, page_size);
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

static
int _lttng_ust_ctl_snapshot_sample_positions(struct lttng_ust_ring_buffer *buf,
		struct lttng_ust_ctl_consumer_channel *consumer_chan)
{
	return lib_ring_buffer_snapshot_sample_positions(buf,
		&buf->cons_snapshot, &buf->prod_snapshot,
		consumer_chan->chan->priv->rb_chan->handle);
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
	ret = _lttng_ust_ctl_snapshot_sample_positions(buf, consumer_chan);
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

static
void _lttng_ust_ctl_flush_buffer(struct lttng_ust_ring_buffer *buf,
		int producer_active,
		struct lttng_ust_ctl_consumer_channel *consumer_chan)
{
	lib_ring_buffer_switch_slow(buf, producer_active ? SWITCH_ACTIVE : SWITCH_FLUSH,
		consumer_chan->chan->priv->rb_chan->handle);
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
	_lttng_ust_ctl_flush_buffer(buf, producer_active, consumer_chan);
	lttng_ust_sigbus_del_range(&range);
	sigbus_end();
	return 0;
}

static
struct lttng_ust_client_lib_ring_buffer_client_cb *get_client_cb(
		struct lttng_ust_ring_buffer *buf __attribute__((unused)),
		struct lttng_ust_ring_buffer_channel *chan)
{
	struct lttng_ust_client_lib_ring_buffer_client_cb *client_cb;
	const struct lttng_ust_ring_buffer_config *config;

	config = &chan->backend.config;
	if (!config->cb_ptr)
		return NULL;
	client_cb = caa_container_of(config->cb_ptr,
			struct lttng_ust_client_lib_ring_buffer_client_cb,
			parent);
	return client_cb;
}

static
int _lttng_ust_ctl_get_current_timestamp(struct lttng_ust_ring_buffer *buf,
		struct lttng_ust_ring_buffer_channel *chan,
		struct lttng_ust_client_lib_ring_buffer_client_cb *client_cb,
		uint64_t *ts)
{
	return client_cb->current_timestamp(buf, chan, ts);
}

static
int _lttng_ust_ctl_last_activity_timestamp_compare(struct lttng_ust_ring_buffer *buf,
		struct lttng_ust_ring_buffer_channel *chan,
		uint64_t ts)
{
	const struct lttng_ust_ring_buffer_config *config = &chan->backend.config;

	return last_activity_timestamp_compare(config, chan, buf, ts);
}

static
void lttng_ust_ctl_packet_reset(struct lttng_ust_ctl_consumer_packet *packet)
{
	if (packet->p) {
		free(packet->p);
		packet->p = NULL;
	}

	packet->packet_length = 0;
	packet->packet_length_padded = 0;
}

static
int _lttng_ust_ctl_flush_events_or_populate_packet(struct lttng_ust_ctl_consumer_stream *stream,
		struct lttng_ust_ctl_consumer_packet *packet,
		bool *packet_populated, bool *flush_done)
{
	uint64_t sample_time = 0, seq_num = 0, subbuf_idx = 0, events_discarded = 0;
	struct lttng_ust_client_lib_ring_buffer_client_cb *client_cb;
	struct lttng_ust_ring_buffer_backend_counts *counts;
	struct lttng_ust_ring_buffer_channel *chan = NULL;
	unsigned long pos_before = 0, pos_after = 0;
	struct lttng_ust_ring_buffer *buf;
	struct switch_offests;
	int ret;

	buf = stream->buf;
	chan = stream->chan->chan->priv->rb_chan;
	client_cb = get_client_cb(buf, chan);
	if (!client_cb)
		return -ENOSYS;

	/*
	 * The producer position and timestamp are sampled in explicit order
	 * before the active flush done. Once the flush is complete,
	 * if the producer position is unchanged, the packet will populated.
	 *
	 * This is done to avoid a race condition wherein there could be a
	 * new event produced between the time the samples were taken and
	 * the time the flush is done.
	 */
	ret = _lttng_ust_ctl_snapshot_sample_positions(buf, stream->chan);
	if (ret < 0)
		return ret;

	ret = lttng_ust_ctl_snapshot_get_produced(stream, &pos_before);
	if (ret < 0)
		return ret;

	ret = _lttng_ust_ctl_get_current_timestamp(buf, chan, client_cb, &sample_time);
	if (ret < 0)
		return ret;

	ret = client_cb->current_events_discarded(buf, chan, &events_discarded);

	if (ret < 0)
		return ret;

	_lttng_ust_ctl_flush_buffer(buf, 1, stream->chan);
	if (flush_done)
		*flush_done = true;

	ret = _lttng_ust_ctl_snapshot_sample_positions(buf, stream->chan);
	if (ret < 0)
		return ret;

	ret = lttng_ust_ctl_snapshot_get_produced(stream, &pos_after);
	if (ret < 0)
		return ret;

	if (pos_before == pos_after) {

		struct commit_counters_cold *cc_cold;
		uint64_t packet_cnt;

		cc_cold = shmp_index(chan->handle, buf->commit_cold, subbuf_idx);

		if (!cc_cold)
			return -EFAULT;

		/*
		 * The packet may have been previously initialized, but not
		 * necessarily for the current stream therefore it is reset.
		 */
		lttng_ust_ctl_packet_reset(packet);
		if (!packet->p) {
			ret = client_cb->packet_create(&packet->p, &packet->packet_length);
			if (ret < 0)
				return ret;
		}

		/*
		 * To compute the sequence number that the terminal packet should have,
		 * the produced position that was sampled is used to infer the current
		 * subbuffer index.
		 *
		 * As the sequence number isn't actually incremented afterwards, in situations
		 * where there are multiple back-to-back snapshots there may be packets that
		 * share the same sequence number. If a later packet uses the same
		 * sequence number, readers should discard the earlier duplicates
		 * based on the end timestamps.
		 */
		subbuf_idx = subbuf_index(pos_after, chan);
		counts = shmp_index(chan->handle, buf->backend.buf_cnt, subbuf_idx);
		if (!counts)
			return -EINVAL;

		packet_cnt = subbuffer_load_packet_count(chan, buf, chan->handle,
						v_read(&chan->backend.config, &cc_cold->cc_sb),
						subbuf_idx);
		seq_num = chan->backend.num_subbuf * packet_cnt + subbuf_idx;
		ret = client_cb->packet_initialize(buf, chan, packet->p, sample_time,
						sample_time, seq_num, events_discarded,
						&packet->packet_length,
						&packet->packet_length_padded);
		if (ret < 0)
			return ret;

		*packet_populated = true;
	}

	return 0;
}

/*
 * Perform an active flush of the stream.
 *
 * If the producer position doesn't change, the packet is populated. The
 * packet_populated argument is set to `true` if the population occurs,
 * otherwise it is set to `false`.
 *
 * Both packet and packet_populated must be non-NULL.
 *
 * There are cases where the active flush may happen, but later errors
 * cause a failure. To find out if a flush is performed, pass a non-NULL
 * pointer to the the `flush_done` argument.
 */
int lttng_ust_ctl_flush_events_or_populate_packet(struct lttng_ust_ctl_consumer_stream *stream,
		struct lttng_ust_ctl_consumer_packet *packet,
		bool *packet_populated, bool *flush_done)
{
	struct lttng_ust_sigbus_range range;
	int ret;

	assert(packet);
	assert(packet_populated);

	*packet_populated = false;
	if (flush_done)
		*flush_done = false;

	if (!stream)
		return -EINVAL;
	if (sigbus_begin())
		return -EIO;
	lttng_ust_sigbus_add_range(&range, stream->memory_map_addr, stream->memory_map_size);
	ret = _lttng_ust_ctl_flush_events_or_populate_packet(stream, packet, packet_populated, flush_done);
	lttng_ust_sigbus_del_range(&range);
	sigbus_end();
	return ret;
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
	ret = client_cb->events_discarded_end(buf, chan, events_discarded);
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
	ret = _lttng_ust_ctl_get_current_timestamp(buf, chan, client_cb, ts);
	lttng_ust_sigbus_del_range(&range);
	sigbus_end();
	return ret;
}

int lttng_ust_ctl_last_activity_timestamp_compare(struct lttng_ust_ctl_consumer_stream *stream,
		uint64_t ts)
{
	struct lttng_ust_ring_buffer_channel *chan;
	struct lttng_ust_ring_buffer *buf;
	struct lttng_ust_sigbus_range range;
	int ret;

	if (!stream || !ts)
		return -EINVAL;
	buf = stream->buf;
	chan = stream->chan->chan->priv->rb_chan;
	if (sigbus_begin())
		return -EIO;
	lttng_ust_sigbus_add_range(&range, stream->memory_map_addr,
				stream->memory_map_size);
	ret = _lttng_ust_ctl_last_activity_timestamp_compare(buf, chan, ts);
	lttng_ust_sigbus_del_range(&range);
	sigbus_end();
	return ret;
}

int lttng_ust_ctl_timestamp_add(struct lttng_ust_ctl_consumer_stream *stream,
		uint64_t *ts, int64_t delta_ns)
{
	uint64_t freq;
	int64_t delta;

	if (!stream || !ts)
		return -EINVAL;
	freq = stream->chan->clock_freq;
	delta = delta_ns;
	if (freq != 1000000000ULL) {
		delta *= freq;
		delta /= 1000000000ULL;
	}
	*ts += delta;
	return 0;
}

int lttng_ust_ctl_reclaim_reader_subbuf(struct lttng_ust_ctl_consumer_stream *stream)
{
	struct lttng_ust_ring_buffer_channel *chan;
	struct lttng_ust_ring_buffer *buf;
	struct lttng_ust_sigbus_range range;
	int ret;

	if (!stream)
		return -EINVAL;
	buf = stream->buf;
	chan = stream->chan->chan->priv->rb_chan;
	if (sigbus_begin())
		return -EIO;
	lttng_ust_sigbus_add_range(&range, stream->memory_map_addr,
				stream->memory_map_size);
	ret = lib_ring_buffer_reclaim_reader_subbuf(buf, chan->handle);
	lttng_ust_sigbus_del_range(&range);
	sigbus_end();
	return ret;
}

int lttng_ust_ctl_try_exchange_subbuf(struct lttng_ust_ctl_consumer_stream *stream, unsigned long pos)
{
	struct lttng_ust_ring_buffer_channel *chan;
	struct lttng_ust_ring_buffer *buf;
	struct lttng_ust_sigbus_range range;
	int ret;

	if (!stream)
		return -EINVAL;
	buf = stream->buf;
	chan = stream->chan->chan->priv->rb_chan;
	if (sigbus_begin())
		return -EIO;
	lttng_ust_sigbus_add_range(&range, stream->memory_map_addr,
				stream->memory_map_size);
	ret = lib_ring_buffer_try_exchange_subbuf(buf, pos, chan->handle);
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

int lttng_ust_ctl_packet_create(struct lttng_ust_ctl_consumer_packet **packet)
{
	struct lttng_ust_ctl_consumer_packet *new_packet;

	if (!packet)
		return -EINVAL;

	new_packet = zmalloc(sizeof(struct lttng_ust_ctl_consumer_packet));
	if (!new_packet)
		return -ENOMEM;

	*packet = new_packet;
	return 0;
}

void lttng_ust_ctl_packet_destroy(struct lttng_ust_ctl_consumer_packet *packet)
{
	if (!packet)
		return;

	lttng_ust_ctl_packet_reset(packet);
	free(packet);
}

int lttng_ust_ctl_packet_get_buffer(struct lttng_ust_ctl_consumer_packet *packet, void **buffer,
		uint64_t *packet_length, uint64_t *packet_length_padded)
{
	assert(buffer);
	assert(packet_length);
	assert(packet_length_padded);
	if (!packet || !packet->p)
		return -EINVAL;

	*buffer = packet->p;
	*packet_length = packet->packet_length;
	*packet_length_padded = packet->packet_length_padded;
	return 0;
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
	case 3:
		*notify_cmd = LTTNG_UST_CTL_NOTIFY_CMD_KEY;
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
	char **model_emf_uri,
	uint64_t *user_token)
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
	*user_token = msg.user_token;

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
	reply.r.id = id;
	len = ustcomm_send_unix_sock(sock, &reply, sizeof(reply));
	if (len > 0 && len != sizeof(reply))
		return -EIO;
	if (len < 0)
		return len;
	return 0;
}

#ifdef CONFIG_LTTNG_UST_EXPERIMENTAL_COUNTER
/*
 * Returns 0 on success, negative UST or system error value on error.
 */
int lttng_ust_ctl_recv_register_key(int sock,
	int *session_objd,		/* session descriptor (output) */
	int *map_objd,			/* map descriptor (output) */
	uint32_t *dimension,		/*
					 * Against which dimension is
					 * this key expressed. (output)
					 */
	uint64_t **dimension_indexes,	/*
					 * Indexes (output,
					 * dynamically
					 * allocated, must be
					 * free(3)'d by the
					 * caller if function
					 * returns success.)
					 * Contains @dimension
					 * elements.
					 */
	char **key_string,		/*
					 * key string (output,
					 * dynamically allocated, must
					 * be free(3)'d by the caller if
					 * function returns success.)
					 */
	uint64_t *user_token)
{
	ssize_t len;
	struct ustcomm_notify_key_msg msg;
	size_t dimension_indexes_len, key_string_len;
	uint64_t *a_dimension_indexes = NULL;
	char *a_key_string = NULL;

	len = ustcomm_recv_unix_sock(sock, &msg, sizeof(msg));
	if (len > 0 && len != sizeof(msg))
		return -EIO;
	if (len == 0)
		return -EPIPE;
	if (len < 0)
		return len;

	*session_objd = msg.session_objd;
	*map_objd = msg.map_objd;
	*dimension = msg.dimension;
	dimension_indexes_len = msg.dimension * sizeof(uint64_t);
	key_string_len = msg.key_string_len;
	*user_token = msg.user_token;

	if (dimension_indexes_len) {
		/* recv dimension_indexes */
		a_dimension_indexes = zmalloc(dimension_indexes_len);
		if (!a_dimension_indexes) {
			len = -ENOMEM;
			goto error;
		}
		len = ustcomm_recv_unix_sock(sock, a_dimension_indexes, dimension_indexes_len);
		if (len > 0 && len != dimension_indexes_len) {
			len = -EIO;
			goto error;
		}
		if (len == 0) {
			len = -EPIPE;
			goto error;
		}
		if (len < 0) {
			goto error;
		}
	}

	if (key_string_len) {
		/* recv key_string */
		a_key_string = zmalloc(key_string_len);
		if (!a_key_string) {
			len = -ENOMEM;
			goto error;
		}
		len = ustcomm_recv_unix_sock(sock, a_key_string, key_string_len);
		if (len > 0 && len != key_string_len) {
			len = -EIO;
			goto error;
		}
		if (len == 0) {
			len = -EPIPE;
			goto error;
		}
		if (len < 0) {
			goto error;
		}
		/* Enforce end of string */
		a_key_string[key_string_len - 1] = '\0';
	}

	*dimension_indexes = a_dimension_indexes;
	*key_string = a_key_string;
	return 0;

error:
	free(a_key_string);
	free(a_dimension_indexes);
	return len;
}

/*
 * Returns 0 on success, negative error value on error.
 */
int lttng_ust_ctl_reply_register_key(int sock,
	uint64_t index,			/* Index within dimension (input) */
	int ret_code)			/* return code. 0 ok, negative error */
{
	ssize_t len;
	struct {
		struct ustcomm_notify_hdr header;
		struct ustcomm_notify_key_reply r;
	} reply;

	memset(&reply, 0, sizeof(reply));
	reply.header.notify_cmd = LTTNG_UST_CTL_NOTIFY_CMD_KEY;
	reply.r.ret_code = ret_code;
	reply.r.index = index;
	len = ustcomm_send_unix_sock(sock, &reply, sizeof(reply));
	if (len > 0 && len != sizeof(reply))
		return -EIO;
	if (len < 0)
		return len;
	return 0;
}
#endif	/* CONFIG_LTTNG_UST_EXPERIMENTAL_COUNTER */

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
	DEFINE_ZEROED(struct ustcomm_ust_msg_header, lum);
	DEFINE_ZEROED(struct ustcomm_ust_reply, lur);
	int ret;

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
	return get_possible_cpus_array_len();
}

struct lttng_ust_ctl_daemon_counter *
	lttng_ust_ctl_create_counter(size_t nr_dimensions,
		const struct lttng_ust_ctl_counter_dimension *dimensions,
		int64_t global_sum_step,
		int channel_counter_fd,
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

	case LTTNG_UST_CTL_COUNTER_ALLOC_PER_CPU | LTTNG_UST_CTL_COUNTER_ALLOC_PER_CHANNEL:
	case LTTNG_UST_CTL_COUNTER_ALLOC_PER_CHANNEL:
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
		switch (dimensions[i].key_type) {
		case LTTNG_UST_CTL_KEY_TYPE_TOKENS:
			ust_dim[i].key_type = LTTNG_KEY_TYPE_TOKENS;
			break;
		case LTTNG_UST_CTL_KEY_TYPE_INTEGER:	/* Fall-through */
		default:
			goto free_attr;
		}
	}
	counter->counter = transport->ops.priv->counter_create(nr_dimensions,
		ust_dim, global_sum_step, channel_counter_fd,
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
	struct lttng_ust_abi_counter_conf *counter_conf = NULL;
	struct lttng_ust_abi_counter_dimension *dimension;
	uint32_t conf_len = sizeof(struct lttng_ust_abi_counter_conf) +
				sizeof(struct lttng_ust_abi_counter_dimension);
	struct lttng_ust_abi_object_data *counter_data;
	int ret;

	if (counter->attr->nr_dimensions != 1) {
		ret = -EINVAL;
		goto error;
	}
	counter_conf = zmalloc(conf_len);
	if (!counter_conf) {
		ret = -ENOMEM;
		goto error;
	}
	counter_conf->len = sizeof(struct lttng_ust_abi_counter_conf);
	counter_conf->flags |= counter->attr->coalesce_hits ? LTTNG_UST_ABI_COUNTER_CONF_FLAG_COALESCE_HITS : 0;
	switch (counter->attr->arithmetic) {
	case LTTNG_UST_CTL_COUNTER_ARITHMETIC_MODULAR:
		counter_conf->arithmetic = LTTNG_UST_ABI_COUNTER_ARITHMETIC_MODULAR;
		break;
	case LTTNG_UST_CTL_COUNTER_ARITHMETIC_SATURATION:
		counter_conf->arithmetic = LTTNG_UST_ABI_COUNTER_ARITHMETIC_SATURATION;
		break;
	default:
		ret = -EINVAL;
		goto error;
	}
	switch (counter->attr->bitness) {
	case LTTNG_UST_CTL_COUNTER_BITNESS_32:
		counter_conf->bitness = LTTNG_UST_ABI_COUNTER_BITNESS_32;
		break;
	case LTTNG_UST_CTL_COUNTER_BITNESS_64:
		counter_conf->bitness = LTTNG_UST_ABI_COUNTER_BITNESS_64;
		break;
	default:
		return -EINVAL;
	}
	counter_conf->global_sum_step = counter->attr->global_sum_step;

	counter_conf->number_dimensions = 1;
	counter_conf->elem_len = sizeof(struct lttng_ust_abi_counter_dimension);

	dimension = (struct lttng_ust_abi_counter_dimension *)((char *)counter_conf + sizeof(struct lttng_ust_abi_counter_conf));
	dimension->flags |= counter->attr->dimensions[0].has_underflow ? LTTNG_UST_ABI_COUNTER_DIMENSION_FLAG_UNDERFLOW : 0;
	dimension->flags |= counter->attr->dimensions[0].has_overflow ? LTTNG_UST_ABI_COUNTER_DIMENSION_FLAG_OVERFLOW : 0;
	dimension->size = counter->attr->dimensions[0].size;
	dimension->underflow_index = counter->attr->dimensions[0].underflow_index;
	dimension->overflow_index = counter->attr->dimensions[0].overflow_index;
	switch (counter->attr->dimensions[0].key_type) {
	case LTTNG_UST_CTL_KEY_TYPE_TOKENS:
		dimension->key_type = LTTNG_UST_ABI_KEY_TYPE_TOKENS;
		break;
	case LTTNG_UST_CTL_KEY_TYPE_INTEGER:	/* Fall-through */
	default:
		ret = -EINVAL;
		goto error;
	}

	counter_data = zmalloc(sizeof(*counter_data));
	if (!counter_data) {
		ret = -ENOMEM;
		goto error;
	}
	counter_data->header.type = LTTNG_UST_ABI_OBJECT_TYPE_COUNTER;
	counter_data->header.handle = -1;
	counter_data->header.size = conf_len;
	counter_data->type.counter.data = counter_conf;
	*_counter_data = counter_data;

	return 0;

error:
	free(counter_conf);
	return ret;
}

#ifdef CONFIG_LTTNG_UST_EXPERIMENTAL_COUNTER
int lttng_ust_ctl_create_counter_channel_data(struct lttng_ust_ctl_daemon_counter *counter,
		struct lttng_ust_abi_object_data **_counter_channel_data)
{
	struct lttng_ust_abi_object_data *counter_channel_data;
	int ret, fd;
	size_t len;

	if (lttng_counter_get_channel_shm(counter->counter->priv->counter, &fd, &len))
		return -EINVAL;
	counter_channel_data = zmalloc(sizeof(*counter_channel_data));
	if (!counter_channel_data) {
		ret = -ENOMEM;
		goto error_alloc;
	}
	counter_channel_data->header.type = LTTNG_UST_ABI_OBJECT_TYPE_COUNTER_CHANNEL;
	counter_channel_data->header.handle = -1;
	counter_channel_data->header.size = len;
	counter_channel_data->type.counter_channel.shm_fd = fd;
	*_counter_channel_data = counter_channel_data;
	return 0;

error_alloc:
	return ret;
}
#endif	 /* CONFIG_LTTNG_UST_EXPERIMENTAL_COUNTER */

int lttng_ust_ctl_create_counter_cpu_data(struct lttng_ust_ctl_daemon_counter *counter, int cpu,
		struct lttng_ust_abi_object_data **_counter_cpu_data)
{
	struct lttng_ust_abi_object_data *counter_cpu_data;
	int ret, fd;
	size_t len;

	if (lttng_counter_get_cpu_shm(counter->counter->priv->counter, cpu, &fd, &len))
		return -EINVAL;
	counter_cpu_data = zmalloc(sizeof(*counter_cpu_data));
	if (!counter_cpu_data) {
		ret = -ENOMEM;
		goto error_alloc;
	}
	counter_cpu_data->header.type = LTTNG_UST_ABI_OBJECT_TYPE_COUNTER_CPU;
	counter_cpu_data->header.handle = -1;
	counter_cpu_data->header.size = len;
	counter_cpu_data->type.counter_cpu.shm_fd = fd;
	counter_cpu_data->type.counter_cpu.cpu_nr = cpu;
	*_counter_cpu_data = counter_cpu_data;
	return 0;

error_alloc:
	return ret;
}

void lttng_ust_ctl_destroy_counter(struct lttng_ust_ctl_daemon_counter *counter)
{
	counter->ops->priv->counter_destroy(counter->counter);
	free(counter->attr);
	free(counter);
}

/*
 * Protocol for LTTNG_UST_ABI_COUNTER command:
 *
 * - send:     struct ustcomm_ust_msg_header
 * - send:     counter data
 * - receive:  struct ustcomm_ust_reply
 */
int lttng_ust_ctl_send_counter_data_to_ust(int sock, int parent_handle,
		struct lttng_ust_abi_object_data *counter_data)
{
	DEFINE_ZEROED(struct ustcomm_ust_msg_header, lum);
	DEFINE_ZEROED(struct ustcomm_ust_reply, lur);
	struct iovec iov[] = {
		{
			.iov_base = counter_data->type.counter.data,
			.iov_len = counter_data->header.size,
		},
	};
	int ret;

	if (!counter_data)
		return -EINVAL;

	lum.handle = parent_handle;
	lum.cmd = LTTNG_UST_ABI_COUNTER;

	ret = ustcomm_send_app_msg(sock, &lum,
				iov, LTTNG_ARRAY_SIZE(iov),
				NULL, 0);
	if (ret < 0) {
		return ret;
	}

	ret = ustcomm_recv_app_reply(sock, &lur, lum.handle, lum.cmd);
	if (!ret) {
		counter_data->header.handle = lur.header.ret_val;
	}
	return ret;
}

#ifdef CONFIG_LTTNG_UST_EXPERIMENTAL_COUNTER
/*
 * Protocol for LTTNG_UST_ABI_COUNTER_CHANNEL command:
 *
 * - send:     struct ustcomm_ust_msg_header
 * - send:     file descriptor
 * - receive:  struct ustcomm_ust_reply (actual command return code)
 */
int lttng_ust_ctl_send_counter_channel_data_to_ust(int sock,
		struct lttng_ust_abi_object_data *counter_data,
		struct lttng_ust_abi_object_data *counter_channel_data)
{
	DEFINE_ZEROED(struct ustcomm_ust_msg_header, lum);
	DEFINE_ZEROED(struct ustcomm_ust_reply, lur);
	DEFINE_ZEROED(struct lttng_ust_abi_counter_channel, counter_channel);
	struct iovec iov[] = {
		{
			.iov_base = &counter_channel,
			.iov_len = sizeof(counter_channel),
		},
	};
	int fds[] = {
		counter_channel_data->type.counter_channel.shm_fd,
	};
	int ret;

	if (!counter_data || !counter_channel_data)
		return -EINVAL;

	counter_channel.len = sizeof(struct lttng_ust_abi_counter_channel);
	counter_channel.shm_len = counter_channel_data->header.size;

	lum.handle = counter_data->header.handle;	/* parent handle */
	lum.cmd = LTTNG_UST_ABI_COUNTER_CHANNEL;

	ret = ustcomm_send_app_msg(sock, &lum,
				iov, LTTNG_ARRAY_SIZE(iov),
				fds, LTTNG_ARRAY_SIZE(fds));
	if (ret < 0) {
		return ret;
	}

	ret = ustcomm_recv_app_reply(sock, &lur, lum.handle, lum.cmd);
	if (!ret) {
		counter_channel_data->header.handle = lur.header.ret_val;
	}
	return ret;
}
#endif	/* CONFIG_LTTNG_UST_EXPERIMENTAL_COUNTER */

/*
 * Protocol for LTTNG_UST_ABI_COUNTER_CPU command:
 *
 * - send:     struct ustcomm_ust_msg_header
 * - send:     file descriptor
 * - receive:  struct ustcomm_ust_reply (actual command return code)
 */
int lttng_ust_ctl_send_counter_cpu_data_to_ust(int sock,
		struct lttng_ust_abi_object_data *counter_data,
		struct lttng_ust_abi_object_data *counter_cpu_data)
{
	DEFINE_ZEROED(struct ustcomm_ust_msg_header, lum);
	DEFINE_ZEROED(struct ustcomm_ust_reply, lur);
	DEFINE_ZEROED(struct lttng_ust_abi_counter_cpu, counter_cpu);
	struct iovec iov[] = {
		{
			.iov_base = &counter_cpu,
			.iov_len = sizeof(counter_cpu),
		},
	};
	int ret, fds[1];

	if (!counter_data || !counter_cpu_data)
		return -EINVAL;

	fds[0] = counter_cpu_data->type.counter_channel.shm_fd;
	counter_cpu.len = sizeof(struct lttng_ust_abi_counter_cpu);
	counter_cpu.shm_len = counter_cpu_data->header.size;
	counter_cpu.cpu_nr = counter_cpu_data->type.counter_cpu.cpu_nr;

	lum.handle = counter_data->header.handle;	/* parent handle */
	lum.cmd = LTTNG_UST_ABI_COUNTER_CPU;

	ret = ustcomm_send_app_msg(sock, &lum,
				iov, LTTNG_ARRAY_SIZE(iov),
				fds, LTTNG_ARRAY_SIZE(fds));

	if (ret < 0) {
		return ret;
	}

	ret = ustcomm_recv_app_reply(sock, &lur, lum.handle, lum.cmd);
	if (!ret) {
		counter_cpu_data->header.handle = lur.header.ret_val;
	}
	return ret;
}

#ifdef CONFIG_LTTNG_UST_EXPERIMENTAL_COUNTER
int lttng_ust_ctl_counter_read(struct lttng_ust_ctl_daemon_counter *counter,
		const size_t *dimension_indexes,
		int cpu, int64_t *value,
		bool *overflow, bool *underflow)
{
	return counter->ops->priv->counter_read(counter->counter, dimension_indexes, cpu,
			value, overflow, underflow);
}
#endif	/* CONFIG_LTTNG_UST_EXPERIMENTAL_COUNTER */

int lttng_ust_ctl_counter_aggregate(struct lttng_ust_ctl_daemon_counter *counter,
		const size_t *dimension_indexes,
		int64_t *value,
		bool *overflow, bool *underflow)
{
	return counter->ops->priv->counter_aggregate(counter->counter, dimension_indexes,
			value, overflow, underflow);
}

int lttng_ust_ctl_counter_clear(struct lttng_ust_ctl_daemon_counter *counter,
		const size_t *dimension_indexes)
{
	return counter->ops->priv->counter_clear(counter->counter, dimension_indexes);
}

#ifdef CONFIG_LTTNG_UST_EXPERIMENTAL_COUNTER
/*
 * Protocol for LTTNG_UST_COUNTER_EVENT command:
 *
 * - send:     struct ustcomm_ust_msg_header
 * - send:     struct lttng_ust_counter_event
 * - receive:  struct ustcomm_ust_reply (actual command return code)
 */
int lttng_ust_ctl_counter_create_event(int sock,
		struct lttng_ust_abi_counter_event *counter_event,
		size_t counter_event_len,
		struct lttng_ust_abi_object_data *counter_data,
		struct lttng_ust_abi_object_data **_counter_event_data)
{
	DEFINE_ZEROED(struct ustcomm_ust_msg_header, lum);
	DEFINE_ZEROED(struct ustcomm_ust_reply, lur);
	struct iovec iov[] = {
		{
			.iov_base = counter_event,
			.iov_len = counter_event_len,
		},
	};
	struct lttng_ust_abi_object_data *counter_event_data;
	int ret;

	if (!counter_data || !_counter_event_data)
		return -EINVAL;

	counter_event_data = zmalloc(sizeof(*counter_event_data));
	if (!counter_event_data)
		return -ENOMEM;
	counter_event_data->header.type = LTTNG_UST_ABI_OBJECT_TYPE_COUNTER_EVENT;

	lum.handle = counter_data->header.handle;
	lum.cmd = LTTNG_UST_ABI_COUNTER_EVENT;

	ret = ustcomm_send_app_msg(sock, &lum,
				iov, LTTNG_ARRAY_SIZE(iov),
				NULL, 0);
	if (ret < 0) {
		free(counter_event_data);
		return ret;
	}

	ret = ustcomm_recv_app_reply(sock, &lur, lum.handle, lum.cmd);
	if (ret) {
		free(counter_event_data);
		return ret;
	}
	counter_event_data->header.handle = lur.header.ret_val;
	DBG("received counter event handle %u", counter_event_data->header.handle);
	*_counter_event_data = counter_event_data;
	return 0;
}
#endif	 /* CONFIG_LTTNG_UST_EXPERIMENTAL_COUNTER */

int lttng_ust_ctl_get_version(uint32_t *major, uint32_t *minor,
		uint32_t *patchlevel) {
	*major = LTTNG_UST_MAJOR_VERSION;
	*minor = LTTNG_UST_MINOR_VERSION;
	*patchlevel = LTTNG_UST_PATCHLEVEL_VERSION;
	return 0;
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
