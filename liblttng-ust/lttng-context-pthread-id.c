/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2009-2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng UST pthread_id context.
 */

#define _LGPL_SOURCE
#include <stddef.h>
#include <pthread.h>
#include <lttng/ust-events.h>
#include <lttng/ust-tracer.h>
#include <lttng/ringbuffer-config.h>

#include "context-internal.h"

static
size_t pthread_id_get_size(struct lttng_ctx_field *field, size_t offset)
{
	size_t size = 0;

	size += lib_ring_buffer_align(offset, lttng_alignof(unsigned long));
	size += sizeof(unsigned long);
	return size;
}

static
void pthread_id_record(struct lttng_ctx_field *field,
		 struct lttng_ust_lib_ring_buffer_ctx *ctx,
		 struct lttng_channel *chan)
{
	unsigned long pthread_id;

	pthread_id = (unsigned long) pthread_self();
	lib_ring_buffer_align_ctx(ctx, lttng_alignof(pthread_id));
	chan->ops->event_write(ctx, &pthread_id, sizeof(pthread_id));
}

static
void pthread_id_get_value(struct lttng_ctx_field *field,
		struct lttng_ctx_value *value)
{
	value->u.s64 = (unsigned long) pthread_self();
}

int lttng_add_pthread_id_to_ctx(struct lttng_ctx **ctx)
{
	struct lttng_ctx_field *field;

	field = lttng_append_context(ctx);
	if (!field)
		return -ENOMEM;
	if (lttng_find_context(*ctx, "pthread_id")) {
		lttng_remove_context_field(ctx, field);
		return -EEXIST;
	}
	field->event_field.name = "pthread_id";
	field->event_field.type.atype = atype_integer;
	field->event_field.type.u.integer.size = sizeof(unsigned long) * CHAR_BIT;
	field->event_field.type.u.integer.alignment = lttng_alignof(unsigned long) * CHAR_BIT;
	field->event_field.type.u.integer.signedness = lttng_is_signed_type(unsigned long);
	field->event_field.type.u.integer.reverse_byte_order = 0;
	field->event_field.type.u.integer.base = 10;
	field->event_field.type.u.integer.encoding = lttng_encode_none;
	field->get_size = pthread_id_get_size;
	field->record = pthread_id_record;
	field->get_value = pthread_id_get_value;
	lttng_context_update(*ctx);
	return 0;
}
