/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2013-2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#define _LGPL_SOURCE
#include <stdio.h>
#include "common/macros.h"
#include "common/tracer.h"

/* The tracepoint definition is public, but the provider definition is hidden. */
#define LTTNG_UST_TRACEPOINT_PROVIDER_HIDDEN_DEFINITION

#define LTTNG_UST_TRACEPOINT_CREATE_PROBES
#define LTTNG_UST_TRACEPOINT_DEFINE
#include "lttng-ust-tracef-provider.h"

#include "tracelog-internal.h"

void lttng_ust__vtracef(const char *fmt, va_list ap)
	__attribute__((format(printf, 1, 0)));
void lttng_ust__vtracef(const char *fmt, va_list ap)
{
	LTTNG_UST_TRACELOG_VALIST(fmt, ap,
		lttng_ust_tracepoint_cb_lttng_ust_tracef___event,
		msg, len, LTTNG_UST_CALLER_IP());
}

void lttng_ust__tracef(const char *fmt, ...)
	__attribute__((format(printf, 1, 2)));
void lttng_ust__tracef(const char *fmt, ...)
{
	LTTNG_UST_TRACELOG_VARARG(fmt,
		lttng_ust_tracepoint_cb_lttng_ust_tracef___event,
		msg, len, LTTNG_UST_CALLER_IP());
}
