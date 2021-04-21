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
#include <lttng/ust-ringbuffer-context.h>

#include "context-internal.h"
#include "common/creds.h"


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
size_t veuid_get_size(void *priv __attribute__((unused)),
		size_t offset)
{
	size_t size = 0;

	size += lttng_ust_ring_buffer_align(offset, lttng_ust_rb_alignof(uid_t));
	size += sizeof(uid_t);
	return size;
}

static
void veuid_record(void *priv __attribute__((unused)),
		 struct lttng_ust_ring_buffer_ctx *ctx,
		 struct lttng_ust_channel_buffer *chan)
{
	uid_t veuid;

	veuid = get_veuid();
	chan->ops->event_write(ctx, &veuid, sizeof(veuid), lttng_ust_rb_alignof(veuid));
}

static
void veuid_get_value(void *priv __attribute__((unused)),
		struct lttng_ust_ctx_value *value)
{
	value->u.s64 = get_veuid();
}

static const struct lttng_ust_ctx_field *ctx_field = lttng_ust_static_ctx_field(
	lttng_ust_static_event_field("veuid",
		lttng_ust_static_type_integer(sizeof(uid_t) * CHAR_BIT,
				lttng_ust_rb_alignof(uid_t) * CHAR_BIT,
				lttng_ust_is_signed_type(uid_t),
				LTTNG_UST_BYTE_ORDER, 10),
		false, false),
	veuid_get_size,
	veuid_record,
	veuid_get_value,
	NULL, NULL);

int lttng_add_veuid_to_ctx(struct lttng_ust_ctx **ctx)
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
