/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2009-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2019 Michael Jeanson <mjeanson@efficios.com>
 *
 * LTTng UST uts namespace context.
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
#include <ust-tid.h>
#include <urcu/tls-compat.h>

#include "context-internal.h"
#include "lttng-tracer-core.h"
#include "ns.h"


/*
 * We cache the result to ensure we don't stat(2) the proc filesystem on
 * each event.
 */
static DEFINE_URCU_TLS_INIT(ino_t, cached_uts_ns, NS_INO_UNINITIALIZED);

static
ino_t get_uts_ns(void)
{
	struct stat sb;
	ino_t uts_ns;

	uts_ns = CMM_LOAD_SHARED(URCU_TLS(cached_uts_ns));

	/*
	 * If the cache is populated, do nothing and return the
	 * cached inode number.
	 */
	if (caa_likely(uts_ns != NS_INO_UNINITIALIZED))
		return uts_ns;

	/*
	 * At this point we have to populate the cache, set the initial
	 * value to NS_INO_UNAVAILABLE (0), if we fail to get the inode
	 * number from the proc filesystem, this is the value we will
	 * cache.
	 */
	uts_ns = NS_INO_UNAVAILABLE;

	/*
	 * /proc/thread-self was introduced in kernel v3.17
	 */
	if (stat("/proc/thread-self/ns/uts", &sb) == 0) {
		uts_ns = sb.st_ino;
	} else {
		char proc_ns_path[LTTNG_PROC_NS_PATH_MAX];

		if (snprintf(proc_ns_path, LTTNG_PROC_NS_PATH_MAX,
				"/proc/self/task/%d/ns/uts",
				lttng_gettid()) >= 0) {

			if (stat(proc_ns_path, &sb) == 0) {
				uts_ns = sb.st_ino;
			}
		}
	}

	/*
	 * And finally, store the inode number in the cache.
	 */
	CMM_STORE_SHARED(URCU_TLS(cached_uts_ns), uts_ns);

	return uts_ns;
}

/*
 * The uts namespace can change for 3 reasons
 *  * clone(2) called with CLONE_NEWUTS
 *  * setns(2) called with the fd of a different uts ns
 *  * unshare(2) called with CLONE_NEWUTS
 */
void lttng_context_uts_ns_reset(void)
{
	CMM_STORE_SHARED(URCU_TLS(cached_uts_ns), NS_INO_UNINITIALIZED);
}

static
size_t uts_ns_get_size(struct lttng_ust_ctx_field *field, size_t offset)
{
	size_t size = 0;

	size += lib_ring_buffer_align(offset, lttng_alignof(ino_t));
	size += sizeof(ino_t);
	return size;
}

static
void uts_ns_record(struct lttng_ust_ctx_field *field,
		 struct lttng_ust_lib_ring_buffer_ctx *ctx,
		 struct lttng_ust_channel_buffer *chan)
{
	ino_t uts_ns;

	uts_ns = get_uts_ns();
	lib_ring_buffer_align_ctx(ctx, lttng_alignof(uts_ns));
	chan->ops->event_write(ctx, &uts_ns, sizeof(uts_ns));
}

static
void uts_ns_get_value(struct lttng_ust_ctx_field *field,
		struct lttng_ust_ctx_value *value)
{
	value->u.s64 = get_uts_ns();
}

int lttng_add_uts_ns_to_ctx(struct lttng_ust_ctx **ctx)
{
	struct lttng_ust_ctx_field *field;
	struct lttng_ust_type_common *type;
	int ret;

	type = lttng_ust_create_type_integer(sizeof(ino_t) * CHAR_BIT,
			lttng_alignof(ino_t) * CHAR_BIT,
			lttng_ust_is_signed_type(ino_t),
			BYTE_ORDER, 10);
	if (!type)
		return -ENOMEM;
	field = lttng_append_context(ctx);
	if (!field) {
		ret = -ENOMEM;
		goto error_context;
	}
	if (lttng_find_context(*ctx, "uts_ns")) {
		ret = -EEXIST;
		goto error_find_context;
	}
	field->event_field->name = strdup("uts_ns");
	if (!field->event_field->name) {
		ret = -ENOMEM;
		goto error_name;
	}
	field->event_field->type = type;
	field->get_size = uts_ns_get_size;
	field->record = uts_ns_record;
	field->get_value = uts_ns_get_value;
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
 *  * Force a read (imply TLS fixup for dlopen) of TLS variables.
 *   */
void lttng_fixup_uts_ns_tls(void)
{
	asm volatile ("" : : "m" (URCU_TLS(cached_uts_ns)));
}
