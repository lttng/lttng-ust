/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2009-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng UST Instruction Pointer Context.
 */

#define _LGPL_SOURCE
#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>
#include <lttng/ust-events.h>
#include <lttng/ust-tracer.h>
#include <lttng/ringbuffer-config.h>

#include "context-internal.h"

static
size_t ip_get_size(struct lttng_ctx_field *field, size_t offset)
{
	size_t size = 0;

	size += lib_ring_buffer_align(offset, lttng_alignof(void *));
	size += sizeof(void *);
	return size;
}

static
void ip_record(struct lttng_ctx_field *field,
		 struct lttng_ust_lib_ring_buffer_ctx *ctx,
		 struct lttng_channel *chan)
{
	void *ip;

	ip = ctx->ip;
	lib_ring_buffer_align_ctx(ctx, lttng_alignof(ip));
	chan->ops->event_write(ctx, &ip, sizeof(ip));
}

int lttng_add_ip_to_ctx(struct lttng_ctx **ctx)
{
	struct lttng_ctx_field *field;

	field = lttng_append_context(ctx);
	if (!field)
		return -ENOMEM;
	if (lttng_find_context(*ctx, "ip")) {
		lttng_remove_context_field(ctx, field);
		return -EEXIST;
	}
	field->event_field.name = "ip";
	field->event_field.type.atype = atype_integer;
	field->event_field.type.u.integer.size = sizeof(void *) * CHAR_BIT;
	field->event_field.type.u.integer.alignment = lttng_alignof(void *) * CHAR_BIT;
	field->event_field.type.u.integer.signedness = lttng_is_signed_type(void *);
	field->event_field.type.u.integer.reverse_byte_order = 0;
	field->event_field.type.u.integer.base = 16;
	field->event_field.type.u.integer.encoding = lttng_encode_none;
	field->get_size = ip_get_size;
	field->record = ip_record;
	lttng_context_update(*ctx);
	return 0;
}
