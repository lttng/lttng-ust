/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2013-2015 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _LTTNG_UST_TRACELOG_H
#define _LTTNG_UST_TRACELOG_H

#include <lttng/ust-api-compat.h>
#include <lttng/tp/lttng-ust-tracelog.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LTTNG_UST_TP_TRACELOG_CB_TEMPLATE(level)					\
	extern void lttng_ust__tracelog_##level(const char *file,	\
		int line, const char *func, const char *fmt, ...)	\
		__attribute__ ((format(printf, 4, 5)));			\
									\
	extern void lttng_ust__vtracelog_##level(const char *file,	\
		int line, const char *func, const char *fmt,		\
		va_list ap)						\
		__attribute__ ((format(printf, 4, 0)));

LTTNG_UST_TP_TRACELOG_CB_TEMPLATE(LTTNG_UST_TRACEPOINT_LOGLEVEL_EMERG);
LTTNG_UST_TP_TRACELOG_CB_TEMPLATE(LTTNG_UST_TRACEPOINT_LOGLEVEL_ALERT);
LTTNG_UST_TP_TRACELOG_CB_TEMPLATE(LTTNG_UST_TRACEPOINT_LOGLEVEL_CRIT);
LTTNG_UST_TP_TRACELOG_CB_TEMPLATE(LTTNG_UST_TRACEPOINT_LOGLEVEL_ERR);
LTTNG_UST_TP_TRACELOG_CB_TEMPLATE(LTTNG_UST_TRACEPOINT_LOGLEVEL_WARNING);
LTTNG_UST_TP_TRACELOG_CB_TEMPLATE(LTTNG_UST_TRACEPOINT_LOGLEVEL_NOTICE);
LTTNG_UST_TP_TRACELOG_CB_TEMPLATE(LTTNG_UST_TRACEPOINT_LOGLEVEL_INFO);
LTTNG_UST_TP_TRACELOG_CB_TEMPLATE(LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_SYSTEM);
LTTNG_UST_TP_TRACELOG_CB_TEMPLATE(LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_PROGRAM);
LTTNG_UST_TP_TRACELOG_CB_TEMPLATE(LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_PROCESS);
LTTNG_UST_TP_TRACELOG_CB_TEMPLATE(LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_MODULE);
LTTNG_UST_TP_TRACELOG_CB_TEMPLATE(LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_UNIT);
LTTNG_UST_TP_TRACELOG_CB_TEMPLATE(LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_FUNCTION);
LTTNG_UST_TP_TRACELOG_CB_TEMPLATE(LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_LINE);
LTTNG_UST_TP_TRACELOG_CB_TEMPLATE(LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG);

#undef LTTNG_UST_TP_TRACELOG_CB_TEMPLATE

#define lttng_ust_tracelog(level, fmt, ...)					\
	do {								\
		LTTNG_UST_STAP_PROBEV(tracepoint_lttng_ust_tracelog, level, ## __VA_ARGS__); \
		if (caa_unlikely(lttng_ust_tracepoint_lttng_ust_tracelog___##level.state)) \
			lttng_ust__tracelog_##level(__FILE__, __LINE__, __func__, \
				fmt, ## __VA_ARGS__);			\
	} while (0)

#define lttng_ust_vtracelog(level, fmt, ap)					\
	do {								\
		if (caa_unlikely(lttng_ust_tracepoint_lttng_ust_tracelog___##level.state)) \
			lttng_ust__vtracelog_##level(__FILE__, __LINE__, __func__, \
				fmt, ap);				\
	} while (0)

#if LTTNG_UST_COMPAT_API(0)
#define TP_TRACELOG_CB_TEMPLATE LTTNG_UST_TP_TRACELOG_CB_TEMPLATE
#define tracelog	lttng_ust_tracelog
#define vtracelog	lttng_ust_vtracelog
#endif

#ifdef __cplusplus
}
#endif

#endif /* _LTTNG_UST_TRACELOG_H */
