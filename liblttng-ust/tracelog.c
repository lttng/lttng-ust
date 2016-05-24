/*
 * Copyright (C) 2013-2014  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#define _GNU_SOURCE
#define _LGPL_SOURCE
#include <stdio.h>
#include <helper.h>

#define TRACEPOINT_CREATE_PROBES
#define TRACEPOINT_DEFINE
#include "lttng-ust-tracelog-provider.h"

#define TRACELOG_CB(level) \
	void _lttng_ust_tracelog_##level(const char *file, \
			int line, const char *func, \
			const char *fmt, ...) \
	{ \
		va_list ap; \
		char *msg; \
		int len; \
		\
		va_start(ap, fmt); \
		len = vasprintf(&msg, fmt, ap); \
		/* len does not include the final \0 */ \
		if (len < 0) \
			goto end; \
		__tracepoint_cb_lttng_ust_tracelog___##level(file, \
			line, func, msg, len, \
			LTTNG_UST_CALLER_IP()); \
		free(msg); \
	end: \
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
