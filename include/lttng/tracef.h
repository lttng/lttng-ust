/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2013-2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _LTTNG_UST_TRACEF_H
#define _LTTNG_UST_TRACEF_H

#include <lttng/ust-api-compat.h>
#include <lttng/tp/lttng-ust-tracef.h>

#ifdef __cplusplus
extern "C" {
#endif

extern
void lttng_ust__tracef(const char *fmt, ...)
	__attribute__((format(printf, 1, 2)));

extern
void lttng_ust__vtracef(const char *fmt, va_list ap)
	__attribute__((format(printf, 1, 0)));

#define lttng_ust_tracef(fmt, ...)						\
	do {								\
		LTTNG_UST_STAP_PROBEV(tracepoint_lttng_ust_tracef, event, ## __VA_ARGS__); \
		if (caa_unlikely(lttng_ust_tracepoint_lttng_ust_tracef___event.state)) \
			lttng_ust__tracef(fmt, ## __VA_ARGS__);		\
	} while (0)

#define lttng_ust_vtracef(fmt, ap)						\
	do {								\
		if (caa_unlikely(lttng_ust_tracepoint_lttng_ust_tracef___event.state)) \
			lttng_ust__vtracef(fmt, ap);		\
	} while (0)

#if LTTNG_UST_COMPAT_API(0)
#define tracef		lttng_ust_tracef
#define vtracef		lttng_ust_vtracef
#endif

#ifdef __cplusplus
}
#endif

#endif /* _LTTNG_UST_TRACEF_H */
