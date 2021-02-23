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
#include <lttng/ringbuffer-config.h>
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
void lttng_context_procname_reset(void)
{
	CMM_STORE_SHARED(URCU_TLS(cached_procname)[1][0], '\0');
	CMM_STORE_SHARED(URCU_TLS(procname_nesting), 1);
	CMM_STORE_SHARED(URCU_TLS(cached_procname)[0][0], '\0');
	CMM_STORE_SHARED(URCU_TLS(procname_nesting), 0);
}

static
size_t procname_get_size(struct lttng_ctx_field *field, size_t offset)
{
	return LTTNG_UST_ABI_PROCNAME_LEN;
}

static
void procname_record(struct lttng_ctx_field *field,
		 struct lttng_ust_lib_ring_buffer_ctx *ctx,
		 struct lttng_channel *chan)
{
	char *procname;

	procname = wrapper_getprocname();
	chan->ops->event_write(ctx, procname, LTTNG_UST_ABI_PROCNAME_LEN);
}

static
void procname_get_value(struct lttng_ctx_field *field,
		struct lttng_ctx_value *value)
{
	value->u.str = wrapper_getprocname();
}

static const struct lttng_type procname_array_elem_type =
	__type_integer(char, BYTE_ORDER, 10, UTF8);

int lttng_add_procname_to_ctx(struct lttng_ctx **ctx)
{
	struct lttng_ctx_field *field;

	field = lttng_append_context(ctx);
	if (!field)
		return -ENOMEM;
	if (lttng_find_context(*ctx, "procname")) {
		lttng_remove_context_field(ctx, field);
		return -EEXIST;
	}
	field->event_field.name = "procname";
	field->event_field.type.atype = atype_array_nestable;
	field->event_field.type.u.array_nestable.elem_type =
		&procname_array_elem_type;
	field->event_field.type.u.array_nestable.length = LTTNG_UST_ABI_PROCNAME_LEN;
	field->get_size = procname_get_size;
	field->record = procname_record;
	field->get_value = procname_get_value;
	lttng_context_update(*ctx);
	return 0;
}

/*
 * Force a read (imply TLS fixup for dlopen) of TLS variables.
 */
void lttng_fixup_procname_tls(void)
{
	asm volatile ("" : : "m" (URCU_TLS(cached_procname)[0]));
}
