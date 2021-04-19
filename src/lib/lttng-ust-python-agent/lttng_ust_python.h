/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2014 - David Goulet <dgoulet@efficios.com>
 */

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER lttng_python

#if !defined(_TRACEPOINT_LTTNG_UST_PYTHON_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
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
		ctf_string(asctime, asctime)
		ctf_string(msg, msg)
		ctf_string(logger_name, logger_name)
		ctf_string(funcName, funcName)
		ctf_integer(unsigned int, lineno, lineno)
		ctf_integer(unsigned int, int_loglevel, int_loglevel)
		ctf_integer(unsigned int, thread, thread)
		ctf_string(threadName, threadName)
	)
)

#endif /* _TRACEPOINT_LTTNG_UST_PYTHON_H */

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./lttng_ust_python.h"

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>
