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
#include "lttng-ust-tracelog-provider.h"

#include "tracelog-internal.h"

#define LTTNG_UST_TRACELOG_CB(level) \
	void lttng_ust__vtracelog_##level(const char *file, \
			int line, const char *func, \
			const char *fmt, va_list ap) \
		__attribute__ ((format(printf, 4, 0))); \
	\
	void lttng_ust__vtracelog_##level(const char *file, \
			int line, const char *func, \
			const char *fmt, va_list ap); \
	void lttng_ust__vtracelog_##level(const char *file, \
			int line, const char *func, \
			const char *fmt, va_list ap) \
	{ \
		LTTNG_UST_TRACELOG_VALIST(fmt, ap, \
			lttng_ust_tracepoint_cb_lttng_ust_tracelog___##level, \
			file, line, func, msg, len, LTTNG_UST_CALLER_IP()); \
	} \
	\
	void lttng_ust__tracelog_##level(const char *file, \
			int line, const char *func, \
			const char *fmt, ...) \
		__attribute__ ((format(printf, 4, 5))); \
	\
	void lttng_ust__tracelog_##level(const char *file, \
			int line, const char *func, \
			const char *fmt, ...); \
	void lttng_ust__tracelog_##level(const char *file, \
			int line, const char *func, \
			const char *fmt, ...) \
	{ \
		LTTNG_UST_TRACELOG_VARARG(fmt, \
			lttng_ust_tracepoint_cb_lttng_ust_tracelog___##level, \
			file, line, func, msg, len, LTTNG_UST_CALLER_IP()); \
	}

LTTNG_UST_TRACELOG_CB(LTTNG_UST_TRACEPOINT_LOGLEVEL_EMERG)
LTTNG_UST_TRACELOG_CB(LTTNG_UST_TRACEPOINT_LOGLEVEL_ALERT)
LTTNG_UST_TRACELOG_CB(LTTNG_UST_TRACEPOINT_LOGLEVEL_CRIT)
LTTNG_UST_TRACELOG_CB(LTTNG_UST_TRACEPOINT_LOGLEVEL_ERR)
LTTNG_UST_TRACELOG_CB(LTTNG_UST_TRACEPOINT_LOGLEVEL_WARNING)
LTTNG_UST_TRACELOG_CB(LTTNG_UST_TRACEPOINT_LOGLEVEL_NOTICE)
LTTNG_UST_TRACELOG_CB(LTTNG_UST_TRACEPOINT_LOGLEVEL_INFO)
LTTNG_UST_TRACELOG_CB(LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_SYSTEM)
LTTNG_UST_TRACELOG_CB(LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_PROGRAM)
LTTNG_UST_TRACELOG_CB(LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_PROCESS)
LTTNG_UST_TRACELOG_CB(LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_MODULE)
LTTNG_UST_TRACELOG_CB(LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_UNIT)
LTTNG_UST_TRACELOG_CB(LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_FUNCTION)
LTTNG_UST_TRACELOG_CB(LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_LINE)
LTTNG_UST_TRACELOG_CB(LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG)
