/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2009-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng UST vpid context.
 */

#define _LGPL_SOURCE
#include <limits.h>
#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>
#include <lttng/ust-events.h>
#include <lttng/ust-tracer.h>
#include <lttng/ust-ringbuffer-context.h>

#include "context-internal.h"

/*
 * We cache the result to ensure we don't trigger a system call for
 * each event.
 */
static pid_t cached_vpid;

static inline
pid_t wrapper_getvpid(void)
{
	pid_t vpid;

	vpid = CMM_LOAD_SHARED(cached_vpid);
	if (caa_unlikely(!vpid)) {
		vpid = getpid();
		CMM_STORE_SHARED(cached_vpid, vpid);
	}
	return vpid;
}

/*
 * Upon fork or clone, the PID assigned to our thread is not the same as
 * we kept in cache.
 */
void lttng_context_vpid_reset(void)
{
	CMM_STORE_SHARED(cached_vpid, 0);
}

static
size_t vpid_get_size(void *priv __attribute__((unused)),
		size_t offset)
{
	size_t size = 0;

	size += lttng_ust_ring_buffer_align(offset, lttng_ust_rb_alignof(pid_t));
	size += sizeof(pid_t);
	return size;
}

static
void vpid_record(void *priv __attribute__((unused)),
		 struct lttng_ust_ring_buffer_ctx *ctx,
		 struct lttng_ust_channel_buffer *chan)
{
	pid_t vpid = wrapper_getvpid();

	chan->ops->event_write(ctx, &vpid, sizeof(vpid), lttng_ust_rb_alignof(vpid));
}

static
void vpid_get_value(void *priv __attribute__((unused)),
		struct lttng_ust_ctx_value *value)
{
	value->u.s64 = wrapper_getvpid();
}

static const struct lttng_ust_ctx_field *ctx_field = lttng_ust_static_ctx_field(
	lttng_ust_static_event_field("vpid",
		lttng_ust_static_type_integer(sizeof(pid_t) * CHAR_BIT,
				lttng_ust_rb_alignof(pid_t) * CHAR_BIT,
				lttng_ust_is_signed_type(pid_t),
				LTTNG_UST_BYTE_ORDER, 10),
		false, false),
	vpid_get_size,
	vpid_record,
	vpid_get_value,
	NULL, NULL);

int lttng_add_vpid_to_ctx(struct lttng_ust_ctx **ctx)
{
	int ret;

	if (lttng_find_context(*ctx, ctx_field->event_field->name)) {
		ret = -EEXIST;
		goto error_find_context;
	}
	ret = lttng_ust_context_append(ctx, ctx_field);
	if (ret)
		return ret;
	return 0;

error_find_context:
	return ret;
}
