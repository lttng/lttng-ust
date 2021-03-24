/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2009-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2019 Michael Jeanson <mjeanson@efficios.com>
 *
 * LTTng UST namespaced effective group ID context.
 */

#define _LGPL_SOURCE
#include <limits.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <lttng/ust-events.h>
#include <lttng/ust-tracer.h>
#include <lttng/ringbuffer-context.h>

#include "context-internal.h"
#include "creds.h"


/*
 * At the kernel level, user IDs and group IDs are a per-thread attribute.
 * However, POSIX requires that all threads in a process share the same
 * credentials. The NPTL threading implementation handles the POSIX
 * requirements by providing wrapper functions for the various system calls
 * that change process UIDs and GIDs. These wrapper functions (including those
 * for setreuid() and setregid()) employ a signal-based technique to ensure
 * that when one thread changes credentials, all of the other threads in the
 * process also change their credentials.
 */

/*
 * We cache the result to ensure we don't trigger a system call for
 * each event. User / group IDs are global to the process.
 */
static gid_t cached_vegid = INVALID_GID;

static
gid_t get_vegid(void)
{
	gid_t vegid;

	vegid = CMM_LOAD_SHARED(cached_vegid);

	if (caa_unlikely(vegid == INVALID_GID)) {
		vegid = getegid();
		CMM_STORE_SHARED(cached_vegid, vegid);
	}

	return vegid;
}

/*
 * The vegid can change on setuid, setreuid, setresuid and seteuid.
 */
void lttng_context_vegid_reset(void)
{
	CMM_STORE_SHARED(cached_vegid, INVALID_GID);
}

static
size_t vegid_get_size(struct lttng_ust_ctx_field *field, size_t offset)
{
	size_t size = 0;

	size += lttng_ust_lib_ring_buffer_align(offset, lttng_alignof(gid_t));
	size += sizeof(gid_t);
	return size;
}

static
void vegid_record(struct lttng_ust_ctx_field *field,
		 struct lttng_ust_lib_ring_buffer_ctx *ctx,
		 struct lttng_ust_channel_buffer *chan)
{
	gid_t vegid;

	vegid = get_vegid();
	lttng_ust_lib_ring_buffer_align_ctx(ctx, lttng_alignof(vegid));
	chan->ops->event_write(ctx, &vegid, sizeof(vegid));
}

static
void vegid_get_value(struct lttng_ust_ctx_field *field,
		struct lttng_ust_ctx_value *value)
{
	value->u.s64 = get_vegid();
}

int lttng_add_vegid_to_ctx(struct lttng_ust_ctx **ctx)
{
	struct lttng_ust_ctx_field *field;
	struct lttng_ust_type_common *type;
	int ret;

	type = lttng_ust_create_type_integer(sizeof(gid_t) * CHAR_BIT,
			lttng_alignof(gid_t) * CHAR_BIT,
			lttng_ust_is_signed_type(gid_t),
			BYTE_ORDER, 10);
	if (!type)
		return -ENOMEM;
	field = lttng_append_context(ctx);
	if (!field) {
		ret = -ENOMEM;
		goto error_context;
	}
	if (lttng_find_context(*ctx, "vegid")) {
		ret = -EEXIST;
		goto error_find_context;
	}
	field->event_field->name = strdup("vegid");
	if (!field->event_field->name) {
		ret = -ENOMEM;
		goto error_name;
	}
	field->event_field->type = type;
	field->get_size = vegid_get_size;
	field->record = vegid_record;
	field->get_value = vegid_get_value;
	lttng_context_update(*ctx);
	return 0;

error_name:
error_find_context:
	lttng_remove_context_field(ctx, field);
error_context:
	lttng_ust_destroy_type(type);
	return ret;
}
