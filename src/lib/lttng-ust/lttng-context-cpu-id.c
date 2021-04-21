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
#include <limits.h>
#include <lttng/ust-events.h>
#include <lttng/ust-tracer.h>
#include "lib/lttng-ust/getcpu.h"
#include <lttng/ust-ringbuffer-context.h>

#include "context-internal.h"

static
size_t cpu_id_get_size(void *priv __attribute__((unused)),
		size_t offset)
{
	size_t size = 0;

	size += lttng_ust_ring_buffer_align(offset, lttng_ust_rb_alignof(int));
	size += sizeof(int);
	return size;
}

static
void cpu_id_record(void *priv __attribute__((unused)),
		 struct lttng_ust_ring_buffer_ctx *ctx,
		 struct lttng_ust_channel_buffer *chan)
{
	int cpu;

	cpu = lttng_ust_get_cpu();
	chan->ops->event_write(ctx, &cpu, sizeof(cpu), lttng_ust_rb_alignof(cpu));
}

static
void cpu_id_get_value(void *priv __attribute__((unused)),
		struct lttng_ust_ctx_value *value)
{
	value->u.s64 = lttng_ust_get_cpu();
}

static const struct lttng_ust_ctx_field *ctx_field = lttng_ust_static_ctx_field(
	lttng_ust_static_event_field("cpu_id",
		lttng_ust_static_type_integer(sizeof(int) * CHAR_BIT,
				lttng_ust_rb_alignof(int) * CHAR_BIT,
				lttng_ust_is_signed_type(int),
				LTTNG_UST_BYTE_ORDER, 10),
		false, false),
	cpu_id_get_size,
	cpu_id_record,
	cpu_id_get_value,
	NULL, NULL);

int lttng_add_cpu_id_to_ctx(struct lttng_ust_ctx **ctx)
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
