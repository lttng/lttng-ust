/*
 * Copyright (C) 2011-2015  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <lttng/tracepoint.h>
#include <stdarg.h>

TRACEPOINT_EVENT_CLASS(lttng_ust_tracelog, tlclass,
	TP_ARGS(const char *, file, int, line, const char *, func,
		const char *, msg, unsigned int, len, void *, ip),
	TP_FIELDS(
		ctf_integer(int, line, line)
		ctf_string(file, file)
		ctf_string(func, func)
		ctf_sequence_text(char, msg, msg, unsigned int, len)
	)
)

#define TP_TRACELOG_TEMPLATE(_level_enum) \
	TRACEPOINT_EVENT_INSTANCE(lttng_ust_tracelog, tlclass, _level_enum, \
		TP_ARGS(const char *, file, int, line, const char *, func, \
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
