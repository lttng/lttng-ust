/*
 * lttng-context-vpid.c
 *
 * LTTng UST vpid context.
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

#ifdef __linux__
static inline
pid_t wrapper_getpid(void)
{
	return getpid();
}

void lttng_context_vpid_reset(void)
{
}
#else
/*
 * We cache the result to ensure we don't trigger a system call for
 * each event.
 */
static pid_t cached_vpid;

static inline
pid_t wrapper_getpid(void)
{
	if (caa_unlikely(!cached_vpid))
		cached_vpid = getpid();
	return cached_vpid;
}

/*
 * Upon fork or clone, the PID assigned to our thread is not the same as
 * we kept in cache.
 */
void lttng_context_vpid_reset(void)
{
	cached_vpid = 0;
}
#endif

static
size_t vpid_get_size(struct lttng_ctx_field *field, size_t offset)
{
	size_t size = 0;

	size += lib_ring_buffer_align(offset, lttng_alignof(pid_t));
	size += sizeof(pid_t);
	return size;
}

static
void vpid_record(struct lttng_ctx_field *field,
		 struct lttng_ust_lib_ring_buffer_ctx *ctx,
		 struct lttng_channel *chan)
{
	pid_t pid;

	pid = wrapper_getpid();
	lib_ring_buffer_align_ctx(ctx, lttng_alignof(pid));
	chan->ops->event_write(ctx, &pid, sizeof(pid));
}

static
void vpid_get_value(struct lttng_ctx_field *field,
		struct lttng_ctx_value *value)
{
	pid_t pid;

	pid = wrapper_getpid();
	value->u.s64 = pid;
}

int lttng_add_vpid_to_ctx(struct lttng_ctx **ctx)
{
	struct lttng_ctx_field *field;

	field = lttng_append_context(ctx);
	if (!field)
		return -ENOMEM;
	if (lttng_find_context(*ctx, "vpid")) {
		lttng_remove_context_field(ctx, field);
		return -EEXIST;
	}
	field->event_field.name = "vpid";
	field->event_field.type.atype = atype_integer;
	field->event_field.type.u.basic.integer.size = sizeof(pid_t) * CHAR_BIT;
	field->event_field.type.u.basic.integer.alignment = lttng_alignof(pid_t) * CHAR_BIT;
	field->event_field.type.u.basic.integer.signedness = lttng_is_signed_type(pid_t);
	field->event_field.type.u.basic.integer.reverse_byte_order = 0;
	field->event_field.type.u.basic.integer.base = 10;
	field->event_field.type.u.basic.integer.encoding = lttng_encode_none;
	field->get_size = vpid_get_size;
	field->record = vpid_record;
	field->get_value = vpid_get_value;
	lttng_context_update(*ctx);
	return 0;
}
