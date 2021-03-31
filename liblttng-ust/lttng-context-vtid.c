/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2009-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng UST vtid context.
 */

#define _LGPL_SOURCE
#include <limits.h>
#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>
#include <lttng/ust-events.h>
#include <lttng/ust-tracer.h>
#include <lttng/ringbuffer-context.h>
#include <ust-tid.h>
#include <urcu/tls-compat.h>

#include "context-internal.h"
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
	CMM_STORE_SHARED(URCU_TLS(cached_vtid), 0);
}

static
size_t vtid_get_size(struct lttng_ust_ctx_field *field __attribute__((unused)),
		size_t offset)
{
	size_t size = 0;

	size += lttng_ust_lib_ring_buffer_align(offset, lttng_ust_rb_alignof(pid_t));
	size += sizeof(pid_t);
	return size;
}

static inline
pid_t wrapper_getvtid(void)
{
	pid_t vtid;

	vtid = CMM_LOAD_SHARED(URCU_TLS(cached_vtid));
	if (caa_unlikely(!vtid)) {
		vtid = lttng_gettid();
		CMM_STORE_SHARED(URCU_TLS(cached_vtid), vtid);
	}
	return vtid;
}

static
void vtid_record(struct lttng_ust_ctx_field *field __attribute__((unused)),
		 struct lttng_ust_lib_ring_buffer_ctx *ctx,
		 struct lttng_ust_channel_buffer *chan)
{
	pid_t vtid = wrapper_getvtid();

	chan->ops->event_write(ctx, &vtid, sizeof(vtid), lttng_ust_rb_alignof(vtid));
}

static
void vtid_get_value(struct lttng_ust_ctx_field *field __attribute__((unused)),
		struct lttng_ust_ctx_value *value)
{
	value->u.s64 = wrapper_getvtid();
}

int lttng_add_vtid_to_ctx(struct lttng_ust_ctx **ctx)
{
	struct lttng_ust_ctx_field *field;
	struct lttng_ust_type_common *type;
	int ret;

	type = lttng_ust_create_type_integer(sizeof(pid_t) * CHAR_BIT,
			lttng_ust_rb_alignof(pid_t) * CHAR_BIT,
			lttng_ust_is_signed_type(pid_t),
			BYTE_ORDER, 10);
	if (!type)
		return -ENOMEM;
	field = lttng_append_context(ctx);
	if (!field) {
		ret = -ENOMEM;
		goto error_context;
	}
	if (lttng_find_context(*ctx, "vtid")) {
		ret = -EEXIST;
		goto error_find_context;
	}
	field->event_field->name = strdup("vtid");
	if (!field->event_field->name) {
		ret = -ENOMEM;
		goto error_name;
	}
	field->event_field->type = type;
	field->get_size = vtid_get_size;
	field->record = vtid_record;
	field->get_value = vtid_get_value;
	lttng_context_update(*ctx);
	return 0;

error_name:
error_find_context:
	lttng_remove_context_field(ctx, field);
error_context:
	lttng_ust_destroy_type(type);
	return ret;
}

/*
 * Force a read (imply TLS fixup for dlopen) of TLS variables.
 */
void lttng_fixup_vtid_tls(void)
{
	asm volatile ("" : : "m" (URCU_TLS(cached_vtid)));
}
