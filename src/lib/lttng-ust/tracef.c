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
void __lttng_ust_vtracef(const char *fmt, va_list ap)
	__attribute__((always_inline, format(printf, 1, 0)));
static inline
void __lttng_ust_vtracef(const char *fmt, va_list ap)
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

/*
 * FIXME: We should include <lttng/tracef.h> for the declarations here, but it
 * fails with tracepoint magic above my paygrade.
 */

void _lttng_ust_vtracef(const char *fmt, va_list ap)
	__attribute__((format(printf, 1, 0)));
void _lttng_ust_vtracef(const char *fmt, va_list ap)
{
	__lttng_ust_vtracef(fmt, ap);
}

void _lttng_ust_tracef(const char *fmt, ...)
	__attribute__((format(printf, 1, 2)));
void _lttng_ust_tracef(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	__lttng_ust_vtracef(fmt, ap);
	va_end(ap);
}
