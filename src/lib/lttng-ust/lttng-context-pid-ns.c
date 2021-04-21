/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2009-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2019 Michael Jeanson <mjeanson@efficios.com>
 *
 * LTTng UST pid namespace context.
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
#include "common/ns.h"

/*
 * We cache the result to ensure we don't stat(2) the proc filesystem on
 * each event. The PID namespace is global to the process.
 */
static ino_t cached_pid_ns = NS_INO_UNINITIALIZED;

static
ino_t get_pid_ns(void)
{
	struct stat sb;
	ino_t pid_ns;

	pid_ns = CMM_LOAD_SHARED(cached_pid_ns);

	/*
	 * If the cache is populated, do nothing and return the
	 * cached inode number.
	 */
	if (caa_likely(pid_ns != NS_INO_UNINITIALIZED))
		return pid_ns;

	/*
	 * At this point we have to populate the cache, set the initial
	 * value to NS_INO_UNAVAILABLE (0), if we fail to get the inode
	 * number from the proc filesystem, this is the value we will
	 * cache.
	 */
	pid_ns = NS_INO_UNAVAILABLE;

	if (stat("/proc/self/ns/pid", &sb) == 0) {
		pid_ns = sb.st_ino;
	}

	/*
	 * And finally, store the inode number in the cache.
	 */
	CMM_STORE_SHARED(cached_pid_ns, pid_ns);

	return pid_ns;
}

/*
 * A process's PID namespace membership is determined when the process is
 * created and cannot be changed thereafter.
 *
 * The pid namespace can change only on clone(2) / fork(2) :
 *  - clone(2) with the CLONE_NEWPID flag
 *  - clone(2) / fork(2) after a call to unshare(2) with the CLONE_NEWPID flag
 *  - clone(2) / fork(2) after a call to setns(2) with a PID namespace fd
 */
void lttng_context_pid_ns_reset(void)
{
	CMM_STORE_SHARED(cached_pid_ns, NS_INO_UNINITIALIZED);
}

static
size_t pid_ns_get_size(void *priv __attribute__((unused)),
		size_t offset)
{
	size_t size = 0;

	size += lttng_ust_ring_buffer_align(offset, lttng_ust_rb_alignof(ino_t));
	size += sizeof(ino_t);
	return size;
}

static
void pid_ns_record(void *priv __attribute__((unused)),
		 struct lttng_ust_ring_buffer_ctx *ctx,
		 struct lttng_ust_channel_buffer *chan)
{
	ino_t pid_ns;

	pid_ns = get_pid_ns();
	chan->ops->event_write(ctx, &pid_ns, sizeof(pid_ns), lttng_ust_rb_alignof(pid_ns));
}

static
void pid_ns_get_value(void *priv __attribute__((unused)),
		struct lttng_ust_ctx_value *value)
{
	value->u.s64 = get_pid_ns();
}

static const struct lttng_ust_ctx_field *ctx_field = lttng_ust_static_ctx_field(
	lttng_ust_static_event_field("pid_ns",
		lttng_ust_static_type_integer(sizeof(ino_t) * CHAR_BIT,
				lttng_ust_rb_alignof(ino_t) * CHAR_BIT,
				lttng_ust_is_signed_type(ino_t),
				LTTNG_UST_BYTE_ORDER, 10),
		false, false),
	pid_ns_get_size,
	pid_ns_record,
	pid_ns_get_value,
	NULL, NULL);

int lttng_add_pid_ns_to_ctx(struct lttng_ust_ctx **ctx)
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
