#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER lttng_jul

#if !defined(_TRACEPOINT_LTTNG_UST_JUL_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_LTTNG_UST_JUL_H

/*
 * Copyright (C) 2011  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; version 2.1 of
 * the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <lttng/tracepoint.h>

/*
 * Tracepoint used by Java applications using the JUL handler.
 */
TRACEPOINT_EVENT(lttng_jul, event,
	TP_ARGS(
		const char *, msg,
		const char *, logger_name,
		const char *, class_name,
		const char *, method_name,
		long, millis,
		int, log_level,
		int, thread_id),
	TP_FIELDS(
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
