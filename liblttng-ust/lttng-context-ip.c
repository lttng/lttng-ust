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
#include <lttng/ringbuffer-context.h>

#include "context-internal.h"

static
size_t ip_get_size(struct lttng_ust_ctx_field *field, size_t offset)
{
	size_t size = 0;

	size += lib_ring_buffer_align(offset, lttng_alignof(void *));
	size += sizeof(void *);
	return size;
}

static
void ip_record(struct lttng_ust_ctx_field *field,
		 struct lttng_ust_lib_ring_buffer_ctx *ctx,
		 struct lttng_ust_channel_buffer *chan)
{
	void *ip;

	ip = ctx->ip;
	lib_ring_buffer_align_ctx(ctx, lttng_alignof(ip));
	chan->ops->event_write(ctx, &ip, sizeof(ip));
}

int lttng_add_ip_to_ctx(struct lttng_ust_ctx **ctx)
{
	struct lttng_ust_ctx_field *field;
	struct lttng_ust_type_common *type;
	int ret;

	type = lttng_ust_create_type_integer(sizeof(void *) * CHAR_BIT,
			lttng_alignof(void *) * CHAR_BIT,
			lttng_is_signed_type(void *),
			BYTE_ORDER, 16);
	if (!type)
		return -ENOMEM;
	field = lttng_append_context(ctx);
	if (!field) {
		ret = -ENOMEM;
		goto error_context;
	}
	if (lttng_find_context(*ctx, "ip")) {
		ret = -EEXIST;
		goto error_find_context;
	}
	field->event_field->name = strdup("ip");
	if (!field->event_field->name) {
		ret = -ENOMEM;
		goto error_name;
	}
	field->event_field->type = type;
	field->get_size = ip_get_size;
	field->record = ip_record;
	lttng_context_update(*ctx);
	return 0;

error_name:
error_find_context:
	lttng_remove_context_field(ctx, field);
error_context:
	lttng_ust_destroy_type(type);
	return ret;
}
