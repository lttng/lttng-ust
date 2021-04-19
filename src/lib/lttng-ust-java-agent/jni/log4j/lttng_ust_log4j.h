/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER lttng_log4j

#if !defined(_TRACEPOINT_LTTNG_UST_LOG4J_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_LTTNG_UST_LOG4J_H

#include <lttng/tracepoint.h>

/*
 * Tracepoint used by Java applications using the log4j log appender.
 */
LTTNG_UST_TRACEPOINT_EVENT(lttng_log4j, event,
	LTTNG_UST_TP_ARGS(
		const char *, msg,
		const char *, logger_name,
		const char *, class_name,
		const char *, method_name,
		const char *, file_name,
		int, line_number,
		long, timestamp,
		int, log_level,
		const char *, thread_name),
	LTTNG_UST_TP_FIELDS(
		ctf_string(msg, msg)
		ctf_string(logger_name, logger_name)
		ctf_string(class_name, class_name)
		ctf_string(method_name, method_name)
		ctf_string(filename, file_name)
		ctf_integer(int, line_number, line_number)
		ctf_integer(long, timestamp, timestamp)
		ctf_integer(int, int_loglevel, log_level)
		ctf_string(thread_name, thread_name)
	)
)

#endif /* _TRACEPOINT_LTTNG_UST_LOG4J_H */

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./lttng_ust_log4j.h"

/* This part must be outside protection */
#include <lttng/tracepoint-event.h>
