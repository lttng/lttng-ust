/*
 * lttng-context-mnt-ns.c
 *
 * LTTng UST mnt namespace context.
 *
 * Copyright (C) 2009-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *               2019 Michael Jeanson <mjeanson@efficios.com>
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

#include "ns.h"

/*
 * We cache the result to ensure we don't stat(2) the proc filesystem on
 * each event. The mount namespace is global to the process.
 */
static ino_t cached_mnt_ns = NS_INO_UNINITIALIZED;

static
ino_t get_mnt_ns(void)
{
	struct stat sb;
	ino_t mnt_ns;

	mnt_ns = CMM_LOAD_SHARED(cached_mnt_ns);

	/*
	 * If the cache is populated, do nothing and return the
	 * cached inode number.
	 */
	if (caa_likely(mnt_ns != NS_INO_UNINITIALIZED))
		return mnt_ns;

	/*
	 * At this point we have to populate the cache, set the initial
	 * value to NS_INO_UNAVAILABLE (0), if we fail to get the inode
	 * number from the proc filesystem, this is the value we will
	 * cache.
	 */
	mnt_ns = NS_INO_UNAVAILABLE;

	if (stat("/proc/self/ns/mnt", &sb) == 0) {
		mnt_ns = sb.st_ino;
	}

	/*
	 * And finally, store the inode number in the cache.
	 */
	CMM_STORE_SHARED(cached_mnt_ns, mnt_ns);

	return mnt_ns;
}

/*
 * The mnt namespace can change for 3 reasons
 *  * clone(2) called with CLONE_NEWNS
 *  * setns(2) called with the fd of a different mnt ns
 *  * unshare(2) called with CLONE_NEWNS
 */
void lttng_context_mnt_ns_reset(void)
{
	CMM_STORE_SHARED(cached_mnt_ns, NS_INO_UNINITIALIZED);
}

static
size_t mnt_ns_get_size(struct lttng_ctx_field *field, size_t offset)
{
	size_t size = 0;

	size += lib_ring_buffer_align(offset, lttng_alignof(ino_t));
	size += sizeof(ino_t);
	return size;
}

static
void mnt_ns_record(struct lttng_ctx_field *field,
		 struct lttng_ust_lib_ring_buffer_ctx *ctx,
		 struct lttng_channel *chan)
{
	ino_t mnt_ns;

	mnt_ns = get_mnt_ns();
	lib_ring_buffer_align_ctx(ctx, lttng_alignof(mnt_ns));
	chan->ops->event_write(ctx, &mnt_ns, sizeof(mnt_ns));
}

static
void mnt_ns_get_value(struct lttng_ctx_field *field,
		struct lttng_ctx_value *value)
{
	value->u.s64 = get_mnt_ns();
}

int lttng_add_mnt_ns_to_ctx(struct lttng_ctx **ctx)
{
	struct lttng_ctx_field *field;

	field = lttng_append_context(ctx);
	if (!field)
		return -ENOMEM;
	if (lttng_find_context(*ctx, "mnt_ns")) {
		lttng_remove_context_field(ctx, field);
		return -EEXIST;
	}
	field->event_field.name = "mnt_ns";
	field->event_field.type.atype = atype_integer;
	field->event_field.type.u.basic.integer.size = sizeof(ino_t) * CHAR_BIT;
	field->event_field.type.u.basic.integer.alignment = lttng_alignof(ino_t) * CHAR_BIT;
	field->event_field.type.u.basic.integer.signedness = lttng_is_signed_type(ino_t);
	field->event_field.type.u.basic.integer.reverse_byte_order = 0;
	field->event_field.type.u.basic.integer.base = 10;
	field->event_field.type.u.basic.integer.encoding = lttng_encode_none;
	field->get_size = mnt_ns_get_size;
	field->record = mnt_ns_record;
	field->get_value = mnt_ns_get_value;
	lttng_context_update(*ctx);
	return 0;
}
