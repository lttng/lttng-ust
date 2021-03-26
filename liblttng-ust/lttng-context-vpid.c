/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2009-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng UST vpid context.
 */

#define _LGPL_SOURCE
#include <limits.h>
#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>
#include <lttng/ust-events.h>
#include <lttng/ust-tracer.h>
#include <lttng/ringbuffer-context.h>

#include "context-internal.h"

/*
 * We cache the result to ensure we don't trigger a system call for
 * each event.
 */
static pid_t cached_vpid;

static inline
pid_t wrapper_getvpid(void)
{
	pid_t vpid;

	vpid = CMM_LOAD_SHARED(cached_vpid);
	if (caa_unlikely(!vpid)) {
		vpid = getpid();
		CMM_STORE_SHARED(cached_vpid, vpid);
	}
	return vpid;
}

/*
 * Upon fork or clone, the PID assigned to our thread is not the same as
 * we kept in cache.
 */
void lttng_context_vpid_reset(void)
{
	CMM_STORE_SHARED(cached_vpid, 0);
}

static
size_t vpid_get_size(struct lttng_ust_ctx_field *field, size_t offset)
{
	size_t size = 0;

	size += lttng_ust_lib_ring_buffer_align(offset, lttng_ust_rb_alignof(pid_t));
	size += sizeof(pid_t);
	return size;
}

static
void vpid_record(struct lttng_ust_ctx_field *field,
		 struct lttng_ust_lib_ring_buffer_ctx *ctx,
		 struct lttng_ust_channel_buffer *chan)
{
	pid_t vpid = wrapper_getvpid();

	lttng_ust_lib_ring_buffer_align_ctx(ctx, lttng_ust_rb_alignof(vpid));
	chan->ops->event_write(ctx, &vpid, sizeof(vpid));
}

static
void vpid_get_value(struct lttng_ust_ctx_field *field,
		struct lttng_ust_ctx_value *value)
{
	value->u.s64 = wrapper_getvpid();
}

int lttng_add_vpid_to_ctx(struct lttng_ust_ctx **ctx)
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
	if (lttng_find_context(*ctx, "vpid")) {
		ret = -EEXIST;
		goto error_find_context;
	}
	field->event_field->name = strdup("vpid");
	if (!field->event_field->name) {
		ret = -ENOMEM;
		goto error_name;
	}
	field->event_field->type = type;
	field->get_size = vpid_get_size;
	field->record = vpid_record;
	field->get_value = vpid_get_value;
	lttng_context_update(*ctx);
	return 0;

error_name:
error_find_context:
	lttng_remove_context_field(ctx, field);
error_context:
	lttng_ust_destroy_type(type);
	return ret;
}
