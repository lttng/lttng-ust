/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER lttng_jul

#if !defined(_TRACEPOINT_LTTNG_UST_JUL_H) || defined(LTTNG_UST_TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_LTTNG_UST_JUL_H

#include <lttng/tracepoint.h>

/*
 * Tracepoint used by Java applications using the JUL handler.
 */
LTTNG_UST_TRACEPOINT_EVENT(lttng_jul, event,
	LTTNG_UST_TP_ARGS(
		const char *, msg,
		const char *, logger_name,
		const char *, class_name,
		const char *, method_name,
		long, millis,
		int, log_level,
		int, thread_id),
	LTTNG_UST_TP_FIELDS(
		ctf_string(msg, msg)
		ctf_string(logger_name, logger_name)
		ctf_string(class_name, class_name)
		ctf_string(method_name, method_name)
		ctf_integer(long, long_millis, millis)
		ctf_integer(int, int_loglevel, log_level)
		ctf_integer(int, int_threadid, thread_id)
	)
)

#endif /* _TRACEPOINT_LTTNG_UST_JUL_H */

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./lttng_ust_jul.h"

/* This part must be outside protection */
#include <lttng/tracepoint-event.h>
