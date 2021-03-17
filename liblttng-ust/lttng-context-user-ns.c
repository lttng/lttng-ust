/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2009-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2019 Michael Jeanson <mjeanson@efficios.com>
 *
 * LTTng UST user namespace context.
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
#include "ns.h"

/*
 * We cache the result to ensure we don't stat(2) the proc filesystem on
 * each event. The user namespace is global to the process.
 */
static ino_t cached_user_ns = NS_INO_UNINITIALIZED;

static
ino_t get_user_ns(void)
{
	struct stat sb;
	ino_t user_ns;

	user_ns = CMM_LOAD_SHARED(cached_user_ns);

	/*
	 * If the cache is populated, do nothing and return the
	 * cached inode number.
	 */
	if (caa_likely(user_ns != NS_INO_UNINITIALIZED))
		return user_ns;

	/*
	 * At this point we have to populate the cache, set the initial
	 * value to NS_INO_UNAVAILABLE (0), if we fail to get the inode
	 * number from the proc filesystem, this is the value we will
	 * cache.
	 */
	user_ns = NS_INO_UNAVAILABLE;

	if (stat("/proc/self/ns/user", &sb) == 0) {
		user_ns = sb.st_ino;
	}

	/*
	 * And finally, store the inode number in the cache.
	 */
	CMM_STORE_SHARED(cached_user_ns, user_ns);

	return user_ns;
}

/*
 * The user namespace can change for 3 reasons
 *  * clone(2) called with CLONE_NEWUSER
 *  * setns(2) called with the fd of a different user ns
 *  * unshare(2) called with CLONE_NEWUSER
 */
void lttng_context_user_ns_reset(void)
{
	CMM_STORE_SHARED(cached_user_ns, NS_INO_UNINITIALIZED);
}

static
size_t user_ns_get_size(struct lttng_ust_ctx_field *field, size_t offset)
{
	size_t size = 0;

	size += lib_ring_buffer_align(offset, lttng_alignof(ino_t));
	size += sizeof(ino_t);
	return size;
}

static
void user_ns_record(struct lttng_ust_ctx_field *field,
		 struct lttng_ust_lib_ring_buffer_ctx *ctx,
		 struct lttng_channel *chan)
{
	ino_t user_ns;

	user_ns = get_user_ns();
	lib_ring_buffer_align_ctx(ctx, lttng_alignof(user_ns));
	chan->ops->event_write(ctx, &user_ns, sizeof(user_ns));
}

static
void user_ns_get_value(struct lttng_ust_ctx_field *field,
		struct lttng_ust_ctx_value *value)
{
	value->u.s64 = get_user_ns();
}

int lttng_add_user_ns_to_ctx(struct lttng_ust_ctx **ctx)
{
	struct lttng_ust_ctx_field *field;
	struct lttng_ust_type_common *type;
	int ret;

	type = lttng_ust_create_type_integer(sizeof(ino_t) * CHAR_BIT,
			lttng_alignof(ino_t) * CHAR_BIT,
			lttng_is_signed_type(ino_t),
			BYTE_ORDER, 10);
	if (!type)
		return -ENOMEM;
	field = lttng_append_context(ctx);
	if (!field) {
		ret = -ENOMEM;
		goto error_context;
	}
	if (lttng_find_context(*ctx, "user_ns")) {
		ret = -EEXIST;
		goto error_find_context;
	}
	field->event_field->name = strdup("user_ns");
	if (!field->event_field->name) {
		ret = -ENOMEM;
		goto error_name;
	}
	field->event_field->type = type;
	field->get_size = user_ns_get_size;
	field->record = user_ns_record;
	field->get_value = user_ns_get_value;
	lttng_context_update(*ctx);
	return 0;

error_name:
error_find_context:
	lttng_remove_context_field(ctx, field);
error_context:
	lttng_ust_destroy_type(type);
	return ret;
}
