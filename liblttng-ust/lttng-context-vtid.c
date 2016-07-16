/*
 * lttng-context-vtid.c
 *
 * LTTng UST vtid context.
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
#include <lttng/ust-tid.h>
#include <urcu/tls-compat.h>
#include "lttng-tracer-core.h"

/*
 * We cache the result to ensure we don't trigger a system call for
 * each event.
 */
static DEFINE_URCU_TLS(pid_t, cached_vtid);

/*
 * Upon fork or clone, the TID assigned to our thread is not the same as
 * we kept in cache. Luckily, we are the only thread surviving in the
 * child process, so we can simply clear our cached version.
 */
void lttng_context_vtid_reset(void)
{
	URCU_TLS(cached_vtid) = 0;
}

static
size_t vtid_get_size(struct lttng_ctx_field *field, size_t offset)
{
	size_t size = 0;

	size += lib_ring_buffer_align(offset, lttng_alignof(pid_t));
	size += sizeof(pid_t);
	return size;
}

static
void vtid_record(struct lttng_ctx_field *field,
		 struct lttng_ust_lib_ring_buffer_ctx *ctx,
		 struct lttng_channel *chan)
{
	if (caa_unlikely(!URCU_TLS(cached_vtid)))
		URCU_TLS(cached_vtid) = gettid();
	lib_ring_buffer_align_ctx(ctx, lttng_alignof(URCU_TLS(cached_vtid)));
	chan->ops->event_write(ctx, &URCU_TLS(cached_vtid),
		sizeof(URCU_TLS(cached_vtid)));
}

static
void vtid_get_value(struct lttng_ctx_field *field,
		struct lttng_ctx_value *value)
{
	if (caa_unlikely(!URCU_TLS(cached_vtid)))
		URCU_TLS(cached_vtid) = gettid();
	value->u.s64 = URCU_TLS(cached_vtid);
}

int lttng_add_vtid_to_ctx(struct lttng_ctx **ctx)
{
	struct lttng_ctx_field *field;

	field = lttng_append_context(ctx);
	if (!field)
		return -ENOMEM;
	if (lttng_find_context(*ctx, "vtid")) {
		lttng_remove_context_field(ctx, field);
		return -EEXIST;
	}
	field->event_field.name = "vtid";
	field->event_field.type.atype = atype_integer;
	field->event_field.type.u.basic.integer.size = sizeof(pid_t) * CHAR_BIT;
	field->event_field.type.u.basic.integer.alignment = lttng_alignof(pid_t) * CHAR_BIT;
	field->event_field.type.u.basic.integer.signedness = lttng_is_signed_type(pid_t);
	field->event_field.type.u.basic.integer.reverse_byte_order = 0;
	field->event_field.type.u.basic.integer.base = 10;
	field->event_field.type.u.basic.integer.encoding = lttng_encode_none;
	field->get_size = vtid_get_size;
	field->record = vtid_record;
	field->get_value = vtid_get_value;
	lttng_context_update(*ctx);
	return 0;
}

/*
 * Force a read (imply TLS fixup for dlopen) of TLS variables.
 */
void lttng_fixup_vtid_tls(void)
{
	asm volatile ("" : : "m" (URCU_TLS(cached_vtid)));
}
