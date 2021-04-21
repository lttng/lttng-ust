/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2014 - David Goulet <dgoulet@efficios.com>
 */

#undef LTTNG_UST_TRACEPOINT_PROVIDER
#define LTTNG_UST_TRACEPOINT_PROVIDER lttng_python

#if !defined(_TRACEPOINT_LTTNG_UST_PYTHON_H) || defined(LTTNG_UST_TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_LTTNG_UST_PYTHON_H

#include <lttng/tracepoint.h>
#include <stdbool.h>

LTTNG_UST_TRACEPOINT_EVENT(lttng_python, event,
	LTTNG_UST_TP_ARGS(
		const char *, asctime,
		const char *, msg,
		const char *, logger_name,
		const char *, funcName,
		int, lineno,
		int, int_loglevel,
		int, thread,
		const char *, threadName
	),
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_string(asctime, asctime)
		lttng_ust_field_string(msg, msg)
		lttng_ust_field_string(logger_name, logger_name)
		lttng_ust_field_string(funcName, funcName)
		lttng_ust_field_integer(unsigned int, lineno, lineno)
		lttng_ust_field_integer(unsigned int, int_loglevel, int_loglevel)
		lttng_ust_field_integer(unsigned int, thread, thread)
		lttng_ust_field_string(threadName, threadName)
	)
)

#endif /* _TRACEPOINT_LTTNG_UST_PYTHON_H */

#undef LTTNG_UST_TRACEPOINT_INCLUDE
#define LTTNG_UST_TRACEPOINT_INCLUDE "./lttng_ust_python.h"

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>
