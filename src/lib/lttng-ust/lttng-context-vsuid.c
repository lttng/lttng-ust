/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2009-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2019 Michael Jeanson <mjeanson@efficios.com>
 *
 * LTTng UST namespaced saved set-user ID context.
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
static uid_t cached_vsuid = INVALID_UID;

static
uid_t get_vsuid(void)
{
	uid_t vsuid;

	vsuid = CMM_LOAD_SHARED(cached_vsuid);

	if (caa_unlikely(vsuid == INVALID_UID)) {
		uid_t uid, euid, suid;

		if (getresuid(&uid, &euid, &suid) == 0) {
			vsuid = suid;
			CMM_STORE_SHARED(cached_vsuid, vsuid);
		}
	}

	return vsuid;
}

/*
 * The vsuid can change on setuid, setreuid and setresuid.
 */
void lttng_context_vsuid_reset(void)
{
	CMM_STORE_SHARED(cached_vsuid, INVALID_UID);
}

static
size_t vsuid_get_size(void *priv __attribute__((unused)),
		size_t offset)
{
	size_t size = 0;

	size += lttng_ust_ring_buffer_align(offset, lttng_ust_rb_alignof(uid_t));
	size += sizeof(uid_t);
	return size;
}

static
void vsuid_record(void *priv __attribute__((unused)),
		 struct lttng_ust_ring_buffer_ctx *ctx,
		 struct lttng_ust_channel_buffer *chan)
{
	uid_t vsuid;

	vsuid = get_vsuid();
	chan->ops->event_write(ctx, &vsuid, sizeof(vsuid), lttng_ust_rb_alignof(vsuid));
}

static
void vsuid_get_value(void *priv __attribute__((unused)),
		struct lttng_ust_ctx_value *value)
{
	value->u.s64 = get_vsuid();
}

static const struct lttng_ust_ctx_field *ctx_field = lttng_ust_static_ctx_field(
	lttng_ust_static_event_field("vsuid",
		lttng_ust_static_type_integer(sizeof(uid_t) * CHAR_BIT,
				lttng_ust_rb_alignof(uid_t) * CHAR_BIT,
				lttng_ust_is_signed_type(uid_t),
				LTTNG_UST_BYTE_ORDER, 10),
		false, false),
	vsuid_get_size,
	vsuid_record,
	vsuid_get_value,
	NULL, NULL);

int lttng_add_vsuid_to_ctx(struct lttng_ust_ctx **ctx)
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
