/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2013-2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#define _LGPL_SOURCE
#include <stdio.h>
#include "common/macros.h"

#define TRACEPOINT_CREATE_PROBES
#define TRACEPOINT_DEFINE
#include "lttng-ust-tracelog-provider.h"

#define TRACELOG_CB(level) \
	static inline \
	void __lttng_ust_vtracelog_##level(const char *file, \
			int line, const char *func, \
			const char *fmt, va_list ap) \
		__attribute__((always_inline, format(printf, 4, 0))); \
	\
	static inline \
	void __lttng_ust_vtracelog_##level(const char *file, \
			int line, const char *func, \
			const char *fmt, va_list ap) \
	{ \
		char *msg; \
		const int len = vasprintf(&msg, fmt, ap); \
		\
		/* len does not include the final \0 */ \
		if (len < 0) \
			goto end; \
		lttng_ust_tracepoint_cb_lttng_ust_tracelog___##level(file, \
			line, func, msg, len, \
			LTTNG_UST_CALLER_IP()); \
		free(msg); \
	end: \
		return; \
	} \
	\
	void _lttng_ust_vtracelog_##level(const char *file, \
			int line, const char *func, \
			const char *fmt, va_list ap) \
		__attribute__ ((format(printf, 4, 0))); \
	\
	void _lttng_ust_vtracelog_##level(const char *file, \
			int line, const char *func, \
			const char *fmt, va_list ap); \
	void _lttng_ust_vtracelog_##level(const char *file, \
			int line, const char *func, \
			const char *fmt, va_list ap) \
	{ \
		__lttng_ust_vtracelog_##level(file, line, func, fmt, ap); \
	} \
	\
	void _lttng_ust_tracelog_##level(const char *file, \
			int line, const char *func, \
			const char *fmt, ...) \
		__attribute__ ((format(printf, 4, 5))); \
	\
	void _lttng_ust_tracelog_##level(const char *file, \
			int line, const char *func, \
			const char *fmt, ...); \
	void _lttng_ust_tracelog_##level(const char *file, \
			int line, const char *func, \
			const char *fmt, ...) \
	{ \
		va_list ap; \
		\
		va_start(ap, fmt); \
		__lttng_ust_vtracelog_##level(file, line, func, fmt, ap); \
		va_end(ap); \
	}

TRACELOG_CB(TRACE_EMERG)
TRACELOG_CB(TRACE_ALERT)
TRACELOG_CB(TRACE_CRIT)
TRACELOG_CB(TRACE_ERR)
TRACELOG_CB(TRACE_WARNING)
TRACELOG_CB(TRACE_NOTICE)
TRACELOG_CB(TRACE_INFO)
TRACELOG_CB(TRACE_DEBUG_SYSTEM)
TRACELOG_CB(TRACE_DEBUG_PROGRAM)
TRACELOG_CB(TRACE_DEBUG_PROCESS)
TRACELOG_CB(TRACE_DEBUG_MODULE)
TRACELOG_CB(TRACE_DEBUG_UNIT)
TRACELOG_CB(TRACE_DEBUG_FUNCTION)
TRACELOG_CB(TRACE_DEBUG_LINE)
TRACELOG_CB(TRACE_DEBUG)
