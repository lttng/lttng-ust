/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2009-2015 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng UST CPU id context.
 *
 * Note: threads can be migrated at any point while executing the
 * tracepoint probe. This means the CPU id field (and filter) is only
 * statistical. For instance, even though a user might select a
 * cpu_id==1 filter, there may be few events recorded into the channel
 * appearing from other CPUs, due to migration.
 */

#define _LGPL_SOURCE
#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>
#include <lttng/ust-events.h>
#include <lttng/ust-tracer.h>
#include <lttng/ringbuffer-config.h>
#include "../libringbuffer/getcpu.h"

#include "context-internal.h"

static
size_t cpu_id_get_size(struct lttng_ctx_field *field, size_t offset)
{
	size_t size = 0;

	size += lib_ring_buffer_align(offset, lttng_alignof(int));
	size += sizeof(int);
	return size;
}

static
void cpu_id_record(struct lttng_ctx_field *field,
		 struct lttng_ust_lib_ring_buffer_ctx *ctx,
		 struct lttng_channel *chan)
{
	int cpu;

	cpu = lttng_ust_get_cpu();
	lib_ring_buffer_align_ctx(ctx, lttng_alignof(cpu));
	chan->ops->event_write(ctx, &cpu, sizeof(cpu));
}

static
void cpu_id_get_value(struct lttng_ctx_field *field,
		struct lttng_ctx_value *value)
{
	value->u.s64 = lttng_ust_get_cpu();
}

int lttng_add_cpu_id_to_ctx(struct lttng_ctx **ctx)
{
	struct lttng_ctx_field *field;

	field = lttng_append_context(ctx);
	if (!field)
		return -ENOMEM;
	if (lttng_find_context(*ctx, "cpu_id")) {
		lttng_remove_context_field(ctx, field);
		return -EEXIST;
	}
	field->event_field.name = "cpu_id";
	field->event_field.type.atype = atype_integer;
	field->event_field.type.u.integer.size = sizeof(int) * CHAR_BIT;
	field->event_field.type.u.integer.alignment = lttng_alignof(int) * CHAR_BIT;
	field->event_field.type.u.integer.signedness = lttng_is_signed_type(int);
	field->event_field.type.u.integer.reverse_byte_order = 0;
	field->event_field.type.u.integer.base = 10;
	field->event_field.type.u.integer.encoding = lttng_encode_none;
	field->get_size = cpu_id_get_size;
	field->record = cpu_id_record;
	field->get_value = cpu_id_get_value;
	lttng_context_update(*ctx);
	return 0;
}
