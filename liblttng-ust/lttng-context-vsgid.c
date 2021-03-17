/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2009-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2019 Michael Jeanson <mjeanson@efficios.com>
 *
 * LTTng UST namespaced saved set-group ID context.
 */

#define _LGPL_SOURCE
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
static gid_t cached_vsgid = INVALID_GID;

static
gid_t get_vsgid(void)
{
	gid_t vsgid;

	vsgid = CMM_LOAD_SHARED(cached_vsgid);

	if (caa_unlikely(vsgid == INVALID_GID)) {
		gid_t gid, egid, sgid;

		if (getresgid(&gid, &egid, &sgid) == 0) {
			vsgid = sgid;
			CMM_STORE_SHARED(cached_vsgid, vsgid);
		}
	}

	return vsgid;
}

/*
 * The vsgid can change on setuid, setreuid and setresuid.
 */
void lttng_context_vsgid_reset(void)
{
	CMM_STORE_SHARED(cached_vsgid, INVALID_GID);
}

static
size_t vsgid_get_size(struct lttng_ust_ctx_field *field, size_t offset)
{
	size_t size = 0;

	size += lib_ring_buffer_align(offset, lttng_alignof(gid_t));
	size += sizeof(gid_t);
	return size;
}

static
void vsgid_record(struct lttng_ust_ctx_field *field,
		 struct lttng_ust_lib_ring_buffer_ctx *ctx,
		 struct lttng_channel *chan)
{
	gid_t vsgid;

	vsgid = get_vsgid();
	lib_ring_buffer_align_ctx(ctx, lttng_alignof(vsgid));
	chan->ops->event_write(ctx, &vsgid, sizeof(vsgid));
}

static
void vsgid_get_value(struct lttng_ust_ctx_field *field,
		struct lttng_ust_ctx_value *value)
{
	value->u.s64 = get_vsgid();
}

int lttng_add_vsgid_to_ctx(struct lttng_ust_ctx **ctx)
{
	struct lttng_ust_ctx_field *field;
	struct lttng_ust_type_common *type;
	int ret;

	type = lttng_ust_create_type_integer(sizeof(gid_t) * CHAR_BIT,
			lttng_alignof(gid_t) * CHAR_BIT,
			lttng_is_signed_type(gid_t),
			BYTE_ORDER, 10);
	if (!type)
		return -ENOMEM;
	field = lttng_append_context(ctx);
	if (!field) {
		ret = -ENOMEM;
		goto error_context;
	}
	if (lttng_find_context(*ctx, "vsgid")) {
		ret = -EEXIST;
		goto error_find_context;
	}
	field->event_field->name = strdup("vsgid");
	if (!field->event_field->name) {
		ret = -ENOMEM;
		goto error_name;
	}
	field->event_field->type = type;
	field->get_size = vsgid_get_size;
	field->record = vsgid_record;
	field->get_value = vsgid_get_value;
	lttng_context_update(*ctx);
	return 0;

error_name:
error_find_context:
	lttng_remove_context_field(ctx, field);
error_context:
	lttng_ust_destroy_type(type);
	return ret;
}
