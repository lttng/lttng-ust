/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2009-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng UST Instruction Pointer Context.
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

static
size_t ip_get_size(void *priv __attribute__((unused)),
		size_t offset)
{
	size_t size = 0;

	size += lttng_ust_ring_buffer_align(offset, lttng_ust_rb_alignof(void *));
	size += sizeof(void *);
	return size;
}

static
void ip_record(void *priv __attribute__((unused)),
		 struct lttng_ust_ring_buffer_ctx *ctx,
		 struct lttng_ust_channel_buffer *chan)
{
	void *ip;

	ip = ctx->ip;
	chan->ops->event_write(ctx, &ip, sizeof(ip), lttng_ust_rb_alignof(ip));
}

static const struct lttng_ust_ctx_field *ctx_field = lttng_ust_static_ctx_field(
	lttng_ust_static_event_field("ip",
		lttng_ust_static_type_integer(sizeof(void *) * CHAR_BIT,
				lttng_ust_rb_alignof(void *) * CHAR_BIT,
				lttng_ust_is_signed_type(void *),
				LTTNG_UST_BYTE_ORDER, 10),
		false, false),
	ip_get_size,
	ip_record,
	NULL, NULL, NULL);

int lttng_add_ip_to_ctx(struct lttng_ust_ctx **ctx)
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
