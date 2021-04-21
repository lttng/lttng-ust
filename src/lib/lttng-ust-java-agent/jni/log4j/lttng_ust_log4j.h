/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#undef LTTNG_UST_TRACEPOINT_PROVIDER
#define LTTNG_UST_TRACEPOINT_PROVIDER lttng_log4j

#if !defined(_TRACEPOINT_LTTNG_UST_LOG4J_H) || defined(LTTNG_UST_TRACEPOINT_HEADER_MULTI_READ)
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
		lttng_ust_field_string(msg, msg)
		lttng_ust_field_string(logger_name, logger_name)
		lttng_ust_field_string(class_name, class_name)
		lttng_ust_field_string(method_name, method_name)
		lttng_ust_field_string(filename, file_name)
		lttng_ust_field_integer(int, line_number, line_number)
		lttng_ust_field_integer(long, timestamp, timestamp)
		lttng_ust_field_integer(int, int_loglevel, log_level)
		lttng_ust_field_string(thread_name, thread_name)
	)
)

#endif /* _TRACEPOINT_LTTNG_UST_LOG4J_H */

#undef LTTNG_UST_TRACEPOINT_INCLUDE
#define LTTNG_UST_TRACEPOINT_INCLUDE "./lttng_ust_log4j.h"

/* This part must be outside protection */
#include <lttng/tracepoint-event.h>
