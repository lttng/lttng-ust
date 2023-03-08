/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2009-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng UST procname context.
 */

#define _LGPL_SOURCE
#include <stddef.h>
#include <lttng/ust-events.h>
#include <lttng/ust-tracer.h>
#include <lttng/ust-ringbuffer-context.h>
#include <urcu/tls-compat.h>
#include <assert.h>
#include "common/compat/pthread.h"
#include "lttng-tracer-core.h"

#include "context-internal.h"

/* Maximum number of nesting levels for the procname cache. */
#define PROCNAME_NESTING_MAX	2

/*
 * We cache the result to ensure we don't trigger a system call for
 * each event.
 * Upon exec, procname changes, but exec takes care of throwing away
 * this cached version.
 * The procname can also change by calling prctl(). The procname should
 * be set for a thread before the first event is logged within this
 * thread.
 */
typedef char procname_array[PROCNAME_NESTING_MAX][LTTNG_UST_CONTEXT_PROCNAME_LEN];

static DEFINE_URCU_TLS(procname_array, cached_procname);

static DEFINE_URCU_TLS(int, procname_nesting);

static inline
const char *wrapper_getprocname(void)
{
	int nesting = CMM_LOAD_SHARED(URCU_TLS(procname_nesting));

	if (caa_unlikely(nesting >= PROCNAME_NESTING_MAX))
		return "<unknown>";
	if (caa_unlikely(!URCU_TLS(cached_procname)[nesting][0])) {
		CMM_STORE_SHARED(URCU_TLS(procname_nesting), nesting + 1);
		/* Increment nesting before updating cache. */
		cmm_barrier();
		lttng_pthread_getname_np(URCU_TLS(cached_procname)[nesting], LTTNG_UST_CONTEXT_PROCNAME_LEN);
		URCU_TLS(cached_procname)[nesting][LTTNG_UST_CONTEXT_PROCNAME_LEN - 1] = '\0';
		/* Decrement nesting after updating cache. */
		cmm_barrier();
		CMM_STORE_SHARED(URCU_TLS(procname_nesting), nesting);
	}
	return URCU_TLS(cached_procname)[nesting];
}

/* Reset should not be called from a signal handler. */
void lttng_ust_context_procname_reset(void)
{
	CMM_STORE_SHARED(URCU_TLS(cached_procname)[1][0], '\0');
	CMM_STORE_SHARED(URCU_TLS(procname_nesting), 1);
	CMM_STORE_SHARED(URCU_TLS(cached_procname)[0][0], '\0');
	CMM_STORE_SHARED(URCU_TLS(procname_nesting), 0);
}

static
size_t procname_get_size(void *priv __attribute__((unused)),
		struct lttng_ust_probe_ctx *probe_ctx __attribute__((unused)),
		size_t offset __attribute__((unused)))
{
	return LTTNG_UST_CONTEXT_PROCNAME_LEN;
}

static
void procname_record(void *priv __attribute__((unused)),
		struct lttng_ust_probe_ctx *probe_ctx __attribute__((unused)),
		struct lttng_ust_ring_buffer_ctx *ctx,
		struct lttng_ust_channel_buffer *chan)
{
	const char *procname;

	procname = wrapper_getprocname();
	chan->ops->event_write(ctx, procname, LTTNG_UST_CONTEXT_PROCNAME_LEN, 1);
}

static
void procname_get_value(void *priv __attribute__((unused)),
		struct lttng_ust_probe_ctx *probe_ctx __attribute__((unused)),
		struct lttng_ust_ctx_value *value)
{
	value->u.str = wrapper_getprocname();
}

static const struct lttng_ust_ctx_field *ctx_field = lttng_ust_static_ctx_field(
	lttng_ust_static_event_field("procname",
		lttng_ust_static_type_array_text(LTTNG_UST_CONTEXT_PROCNAME_LEN),
		false, false),
	procname_get_size,
	procname_record,
	procname_get_value,
	NULL, NULL);

int lttng_add_procname_to_ctx(struct lttng_ust_ctx **ctx)
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

/*
 * Force a read (imply TLS allocation for dlopen) of TLS variables.
 */
void lttng_ust_procname_init_thread(int flags)
{
	__asm__ __volatile__ ("" : : "m" (URCU_TLS(cached_procname)[0]));
	if (flags & LTTNG_UST_INIT_THREAD_CONTEXT_CACHE)
		(void)wrapper_getprocname();
}
