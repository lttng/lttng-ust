/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2013-2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#define _LGPL_SOURCE
#include <stdio.h>
#include "common/macros.h"

#define LTTNG_UST_TRACEPOINT_CREATE_PROBES
#define LTTNG_UST_TRACEPOINT_DEFINE
#include "lttng-ust-tracef-provider.h"

static inline
void lttng_ust___vtracef(const char *fmt, va_list ap)
	__attribute__((always_inline, format(printf, 1, 0)));
static inline
void lttng_ust___vtracef(const char *fmt, va_list ap)
{
	char *msg;
	const int len = vasprintf(&msg, fmt, ap);

	/* len does not include the final \0 */
	if (len < 0)
		goto end;
	lttng_ust_tracepoint_cb_lttng_ust_tracef___event(msg, len,
		LTTNG_UST_CALLER_IP());
	free(msg);
end:
	return;
}

void lttng_ust__vtracef(const char *fmt, va_list ap)
	__attribute__((format(printf, 1, 0)));
void lttng_ust__vtracef(const char *fmt, va_list ap)
{
	lttng_ust___vtracef(fmt, ap);
}

void lttng_ust__tracef(const char *fmt, ...)
	__attribute__((format(printf, 1, 2)));
void lttng_ust__tracef(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	lttng_ust___vtracef(fmt, ap);
	va_end(ap);
}
