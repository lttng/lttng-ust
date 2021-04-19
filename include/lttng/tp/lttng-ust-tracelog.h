/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2011-2015 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include <lttng/tracepoint.h>
#include <stdarg.h>

TRACEPOINT_EVENT_CLASS(lttng_ust_tracelog, tlclass,
	LTTNG_UST_TP_ARGS(const char *, file, int, line, const char *, func,
		const char *, msg, unsigned int, len, void *, ip),
	TP_FIELDS(
		ctf_integer(int, line, line)
		ctf_string(file, file)
		ctf_string(func, func)
		ctf_sequence_text(char, msg, msg, unsigned int, len)
		ctf_unused(ip)
	)
)

#define TP_TRACELOG_TEMPLATE(_level_enum) \
	TRACEPOINT_EVENT_INSTANCE(lttng_ust_tracelog, tlclass, _level_enum, \
		LTTNG_UST_TP_ARGS(const char *, file, int, line, const char *, func, \
			const char *, msg, unsigned int, len, void *, ip) \
	) \
	TRACEPOINT_LOGLEVEL(lttng_ust_tracelog, _level_enum, _level_enum)

TP_TRACELOG_TEMPLATE(TRACE_EMERG)
TP_TRACELOG_TEMPLATE(TRACE_ALERT)
TP_TRACELOG_TEMPLATE(TRACE_CRIT)
TP_TRACELOG_TEMPLATE(TRACE_ERR)
TP_TRACELOG_TEMPLATE(TRACE_WARNING)
TP_TRACELOG_TEMPLATE(TRACE_NOTICE)
TP_TRACELOG_TEMPLATE(TRACE_INFO)
TP_TRACELOG_TEMPLATE(TRACE_DEBUG_SYSTEM)
TP_TRACELOG_TEMPLATE(TRACE_DEBUG_PROGRAM)
TP_TRACELOG_TEMPLATE(TRACE_DEBUG_PROCESS)
TP_TRACELOG_TEMPLATE(TRACE_DEBUG_MODULE)
TP_TRACELOG_TEMPLATE(TRACE_DEBUG_UNIT)
TP_TRACELOG_TEMPLATE(TRACE_DEBUG_FUNCTION)
TP_TRACELOG_TEMPLATE(TRACE_DEBUG_LINE)
TP_TRACELOG_TEMPLATE(TRACE_DEBUG)
