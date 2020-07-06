/*
 * lttng-context-time-ns.c
 *
 * LTTng UST time namespace context.
 *
 * Copyright (C) 2009-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *               2020 Michael Jeanson <mjeanson@efficios.com>
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
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <lttng/ust-events.h>
#include <lttng/ust-tracer.h>
#include <lttng/ringbuffer-config.h>
#include <lttng/ust-tid.h>
#include <urcu/tls-compat.h>
#include "lttng-tracer-core.h"
#include "ns.h"


/*
 * We cache the result to ensure we don't stat(2) the proc filesystem on
 * each event.
 */
static DEFINE_URCU_TLS_INIT(ino_t, cached_time_ns, NS_INO_UNINITIALIZED);

static
ino_t get_time_ns(void)
{
	struct stat sb;
	ino_t time_ns;

	time_ns = CMM_LOAD_SHARED(URCU_TLS(cached_time_ns));

	/*
	 * If the cache is populated, do nothing and return the
	 * cached inode number.
	 */
	if (caa_likely(time_ns != NS_INO_UNINITIALIZED))
		return time_ns;

	/*
	 * At this point we have to populate the cache, set the initial
	 * value to NS_INO_UNAVAILABLE (0), if we fail to get the inode
	 * number from the proc filesystem, this is the value we will
	 * cache.
	 */
	time_ns = NS_INO_UNAVAILABLE;

	/*
	 * /proc/thread-self was introduced in kernel v3.17
	 */
	if (stat("/proc/thread-self/ns/time", &sb) == 0) {
		time_ns = sb.st_ino;
	} else {
		char proc_ns_path[LTTNG_PROC_NS_PATH_MAX];

		if (snprintf(proc_ns_path, LTTNG_PROC_NS_PATH_MAX,
				"/proc/self/task/%d/ns/time",
				lttng_gettid()) >= 0) {

			if (stat(proc_ns_path, &sb) == 0) {
				time_ns = sb.st_ino;
			}
		}
	}

	/*
	 * And finally, store the inode number in the cache.
	 */
	CMM_STORE_SHARED(URCU_TLS(cached_time_ns), time_ns);

	return time_ns;
}

/*
 * The time namespace can change for 2 reasons
 *  * setns(2) called with the fd of a different time ns
 *  * clone(2) / fork(2) after a call to unshare(2) with the CLONE_NEWTIME flag
 */
void lttng_context_time_ns_reset(void)
{
	CMM_STORE_SHARED(URCU_TLS(cached_time_ns), NS_INO_UNINITIALIZED);
}

static
size_t time_ns_get_size(struct lttng_ctx_field *field, size_t offset)
{
	size_t size = 0;

	size += lib_ring_buffer_align(offset, lttng_alignof(ino_t));
	size += sizeof(ino_t);
	return size;
}

static
void time_ns_record(struct lttng_ctx_field *field,
		 struct lttng_ust_lib_ring_buffer_ctx *ctx,
		 struct lttng_channel *chan)
{
	ino_t time_ns;

	time_ns = get_time_ns();
	lib_ring_buffer_align_ctx(ctx, lttng_alignof(time_ns));
	chan->ops->event_write(ctx, &time_ns, sizeof(time_ns));
}

static
void time_ns_get_value(struct lttng_ctx_field *field,
		struct lttng_ctx_value *value)
{
	value->u.s64 = get_time_ns();
}

int lttng_add_time_ns_to_ctx(struct lttng_ctx **ctx)
{
	struct lttng_ctx_field *field;

	field = lttng_append_context(ctx);
	if (!field)
		return -ENOMEM;
	if (lttng_find_context(*ctx, "time_ns")) {
		lttng_remove_context_field(ctx, field);
		return -EEXIST;
	}
	field->event_field.name = "time_ns";
	field->event_field.type.atype = atype_integer;
	field->event_field.type.u.integer.size = sizeof(ino_t) * CHAR_BIT;
	field->event_field.type.u.integer.alignment = lttng_alignof(ino_t) * CHAR_BIT;
	field->event_field.type.u.integer.signedness = lttng_is_signed_type(ino_t);
	field->event_field.type.u.integer.reverse_byte_order = 0;
	field->event_field.type.u.integer.base = 10;
	field->event_field.type.u.integer.encoding = lttng_encode_none;
	field->get_size = time_ns_get_size;
	field->record = time_ns_record;
	field->get_value = time_ns_get_value;
	lttng_context_update(*ctx);
	return 0;
}

/*
 *  * Force a read (imply TLS fixup for dlopen) of TLS variables.
 *   */
void lttng_fixup_time_ns_tls(void)
{
	asm volatile ("" : : "m" (URCU_TLS(cached_time_ns)));
}
