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
#include <lttng/ringbuffer-context.h>
#include <urcu/tls-compat.h>
#include <assert.h>
#include "compat.h"

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
typedef char procname_array[PROCNAME_NESTING_MAX][17];

static DEFINE_URCU_TLS(procname_array, cached_procname);

static DEFINE_URCU_TLS(int, procname_nesting);

static inline
char *wrapper_getprocname(void)
{
	int nesting = CMM_LOAD_SHARED(URCU_TLS(procname_nesting));

	if (caa_unlikely(nesting >= PROCNAME_NESTING_MAX))
		return "<unknown>";
	if (caa_unlikely(!URCU_TLS(cached_procname)[nesting][0])) {
		CMM_STORE_SHARED(URCU_TLS(procname_nesting), nesting + 1);
		/* Increment nesting before updating cache. */
		cmm_barrier();
		lttng_pthread_getname_np(URCU_TLS(cached_procname)[nesting], LTTNG_UST_ABI_PROCNAME_LEN);
		URCU_TLS(cached_procname)[nesting][LTTNG_UST_ABI_PROCNAME_LEN - 1] = '\0';
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
size_t procname_get_size(struct lttng_ust_ctx_field *field, size_t offset)
{
	return LTTNG_UST_ABI_PROCNAME_LEN;
}

static
void procname_record(struct lttng_ust_ctx_field *field,
		 struct lttng_ust_lib_ring_buffer_ctx *ctx,
		 struct lttng_ust_channel_buffer *chan)
{
	char *procname;

	procname = wrapper_getprocname();
	chan->ops->event_write(ctx, procname, LTTNG_UST_ABI_PROCNAME_LEN);
}

static
void procname_get_value(struct lttng_ust_ctx_field *field,
		struct lttng_ust_ctx_value *value)
{
	value->u.str = wrapper_getprocname();
}

int lttng_add_procname_to_ctx(struct lttng_ust_ctx **ctx)
{
	struct lttng_ust_ctx_field *field;
	struct lttng_ust_type_common *type;
	int ret;

	type = lttng_ust_create_type_array_text(LTTNG_UST_ABI_PROCNAME_LEN);
	if (!type)
		return -ENOMEM;
	field = lttng_append_context(ctx);
	if (!field) {
		ret = -ENOMEM;
		goto error_context;
	}
	if (lttng_find_context(*ctx, "procname")) {
		ret = -EEXIST;
		goto error_find_context;
	}
	field->event_field->name = strdup("procname");
	if (!field->event_field->name) {
		ret = -ENOMEM;
		goto error_name;
	}
	field->event_field->type = type;
	field->get_size = procname_get_size;
	field->record = procname_record;
	field->get_value = procname_get_value;
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
 * Force a read (imply TLS fixup for dlopen) of TLS variables.
 */
void lttng_fixup_procname_tls(void)
{
	asm volatile ("" : : "m" (URCU_TLS(cached_procname)[0]));
}
