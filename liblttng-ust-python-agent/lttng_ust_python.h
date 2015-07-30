#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER lttng_python

#if !defined(_TRACEPOINT_LTTNG_UST_PYTHON_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_LTTNG_UST_PYTHON_H

/*
 * Copyright (C) 2014 - David Goulet <dgoulet@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <lttng/tracepoint.h>
#include <stdbool.h>

TRACEPOINT_EVENT(lttng_python, event,
	TP_ARGS(
		const char *, asctime,
		const char *, msg,
		const char *, logger_name,
		const char *, funcName,
		int, lineno,
		int, int_loglevel,
		int, thread,
		const char *, threadName
	),
	TP_FIELDS(
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
