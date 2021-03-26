/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2009-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2019 Michael Jeanson <mjeanson@efficios.com>
 *
 * LTTng UST namespaced effective user ID context.
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
static uid_t cached_veuid = INVALID_UID;

static
uid_t get_veuid(void)
{
	uid_t veuid;

	veuid = CMM_LOAD_SHARED(cached_veuid);

	if (caa_unlikely(veuid == INVALID_UID)) {
		veuid = geteuid();
		CMM_STORE_SHARED(cached_veuid, veuid);
	}

	return veuid;
}

/*
 * The veuid can change on setuid, setreuid, setresuid and seteuid.
 */
void lttng_context_veuid_reset(void)
{
	CMM_STORE_SHARED(cached_veuid, INVALID_UID);
}

static
size_t veuid_get_size(struct lttng_ust_ctx_field *field, size_t offset)
{
	size_t size = 0;

	size += lttng_ust_lib_ring_buffer_align(offset, lttng_ust_rb_alignof(uid_t));
	size += sizeof(uid_t);
	return size;
}

static
void veuid_record(struct lttng_ust_ctx_field *field,
		 struct lttng_ust_lib_ring_buffer_ctx *ctx,
		 struct lttng_ust_channel_buffer *chan)
{
	uid_t veuid;

	veuid = get_veuid();
	lttng_ust_lib_ring_buffer_align_ctx(ctx, lttng_ust_rb_alignof(veuid));
	chan->ops->event_write(ctx, &veuid, sizeof(veuid));
}

static
void veuid_get_value(struct lttng_ust_ctx_field *field,
		struct lttng_ust_ctx_value *value)
{
	value->u.s64 = get_veuid();
}

int lttng_add_veuid_to_ctx(struct lttng_ust_ctx **ctx)
{
	struct lttng_ust_ctx_field *field;
	struct lttng_ust_type_common *type;
	int ret;

	type = lttng_ust_create_type_integer(sizeof(uid_t) * CHAR_BIT,
			lttng_ust_rb_alignof(uid_t) * CHAR_BIT,
			lttng_ust_is_signed_type(uid_t),
			BYTE_ORDER, 10);
	if (!type)
		return -ENOMEM;
	field = lttng_append_context(ctx);
	if (!field) {
		ret = -ENOMEM;
		goto error_context;
	}
	if (lttng_find_context(*ctx, "veuid")) {
		ret = -EEXIST;
		goto error_find_context;
	}
	field->event_field->name = strdup("veuid");
	if (!field->event_field->name) {
		ret = -ENOMEM;
		goto error_name;
	}
	field->event_field->type = type;
	field->get_size = veuid_get_size;
	field->record = veuid_record;
	field->get_value = veuid_get_value;
	lttng_context_update(*ctx);
	return 0;

error_name:
error_find_context:
	lttng_remove_context_field(ctx, field);
error_context:
	lttng_ust_destroy_type(type);
	return ret;
}
