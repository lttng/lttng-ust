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
#include "../libringbuffer/getcpu.h"
#include <lttng/ringbuffer-context.h>

#include "context-internal.h"

static
size_t cpu_id_get_size(struct lttng_ust_ctx_field *field, size_t offset)
{
	size_t size = 0;

	size += lib_ring_buffer_align(offset, lttng_alignof(int));
	size += sizeof(int);
	return size;
}

static
void cpu_id_record(struct lttng_ust_ctx_field *field,
		 struct lttng_ust_lib_ring_buffer_ctx *ctx,
		 struct lttng_ust_channel_buffer *chan)
{
	int cpu;

	cpu = lttng_ust_get_cpu();
	lib_ring_buffer_align_ctx(ctx, lttng_alignof(cpu));
	chan->ops->event_write(ctx, &cpu, sizeof(cpu));
}

static
void cpu_id_get_value(struct lttng_ust_ctx_field *field,
		struct lttng_ust_ctx_value *value)
{
	value->u.s64 = lttng_ust_get_cpu();
}

int lttng_add_cpu_id_to_ctx(struct lttng_ust_ctx **ctx)
{
	struct lttng_ust_ctx_field *field;
	struct lttng_ust_type_common *type;
	int ret;

	type = lttng_ust_create_type_integer(sizeof(int) * CHAR_BIT,
			lttng_alignof(int) * CHAR_BIT,
			lttng_ust_is_signed_type(int),
			BYTE_ORDER, 10);
	if (!type)
		return -ENOMEM;
	field = lttng_append_context(ctx);
	if (!field) {
		ret = -ENOMEM;
		goto error_context;
	}
	if (lttng_find_context(*ctx, "cpu_id")) {
		ret = -EEXIST;
		goto error_find_context;
	}
	field->event_field->name = strdup("cpu_id");
	if (!field->event_field->name) {
		ret = -ENOMEM;
		goto error_name;
	}
	field->event_field->type = type;
	field->get_size = cpu_id_get_size;
	field->record = cpu_id_record;
	field->get_value = cpu_id_get_value;
	lttng_context_update(*ctx);
	return 0;

error_name:
error_find_context:
	lttng_remove_context_field(ctx, field);
error_context:
	lttng_ust_destroy_type(type);
	return ret;
}
