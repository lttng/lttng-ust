/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2009-2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng UST pthread_id context.
 */

#define _LGPL_SOURCE
#include <limits.h>
#include <stddef.h>
#include <pthread.h>
#include <lttng/ust-events.h>
#include <lttng/ust-tracer.h>
#include <lttng/ust-ringbuffer-context.h>

#include "context-internal.h"

static
size_t pthread_id_get_size(void *priv __attribute__((unused)),
		size_t offset)
{
	size_t size = 0;

	size += lttng_ust_ring_buffer_align(offset, lttng_ust_rb_alignof(unsigned long));
	size += sizeof(unsigned long);
	return size;
}

static
void pthread_id_record(void *priv __attribute__((unused)),
		 struct lttng_ust_ring_buffer_ctx *ctx,
		 struct lttng_ust_channel_buffer *chan)
{
	unsigned long pthread_id;

	pthread_id = (unsigned long) pthread_self();
	chan->ops->event_write(ctx, &pthread_id, sizeof(pthread_id), lttng_ust_rb_alignof(pthread_id));
}

static
void pthread_id_get_value(void *priv __attribute__((unused)),
		struct lttng_ust_ctx_value *value)
{
	value->u.s64 = (unsigned long) pthread_self();
}

static const struct lttng_ust_ctx_field *ctx_field = lttng_ust_static_ctx_field(
	lttng_ust_static_event_field("pthread_id",
		lttng_ust_static_type_integer(sizeof(unsigned long) * CHAR_BIT,
				lttng_ust_rb_alignof(unsigned long) * CHAR_BIT,
				lttng_ust_is_signed_type(unsigned long),
				LTTNG_UST_BYTE_ORDER, 10),
		false, false),
	pthread_id_get_size,
	pthread_id_record,
	pthread_id_get_value,
	NULL, NULL);

int lttng_add_pthread_id_to_ctx(struct lttng_ust_ctx **ctx)
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
