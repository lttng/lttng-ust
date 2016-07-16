/*
 * lttng-context-ip.c
 *
 * LTTng UST Instruction Pointer Context.
 *
 * Copyright (C) 2009-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; only
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#define _LGPL_SOURCE
#include <sys/types.h>
#include <unistd.h>
#include <lttng/ust-events.h>
#include <lttng/ust-tracer.h>
#include <lttng/ringbuffer-config.h>

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
	field->event_field.type.u.basic.integer.size = sizeof(void *) * CHAR_BIT;
	field->event_field.type.u.basic.integer.alignment = lttng_alignof(void *) * CHAR_BIT;
	field->event_field.type.u.basic.integer.signedness = lttng_is_signed_type(void *);
	field->event_field.type.u.basic.integer.reverse_byte_order = 0;
	field->event_field.type.u.basic.integer.base = 16;
	field->event_field.type.u.basic.integer.encoding = lttng_encode_none;
	field->get_size = ip_get_size;
	field->record = ip_record;
	lttng_context_update(*ctx);
	return 0;
}
