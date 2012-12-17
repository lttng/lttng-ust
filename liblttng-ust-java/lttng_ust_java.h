#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER lttng_ust_java

#if !defined(_TRACEPOINT_LTTNG_UST_JAVA_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_LTTNG_UST_JAVA_H

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

TRACEPOINT_EVENT(lttng_ust_java, int_event,
	TP_ARGS(const char *, name, int, payload),
	TP_FIELDS(
		ctf_string(name, name)
		ctf_integer(int, int_payload, payload)
	)
)

TRACEPOINT_EVENT(lttng_ust_java, int_int_event,
	TP_ARGS(const char *, name, int, payload1, int, payload2),
	TP_FIELDS(
		ctf_string(name, name)
		ctf_integer(int, int_payload1, payload1)
		ctf_integer(int, int_payload2, payload2)
	)
)

TRACEPOINT_EVENT(lttng_ust_java, long_event,
	TP_ARGS(const char *, name, long, payload),
	TP_FIELDS(
		ctf_string(name, name)
		ctf_integer(long, long_payload, payload)
	)
)

TRACEPOINT_EVENT(lttng_ust_java, long_long_event,
	TP_ARGS(const char *, name, long, payload1, long, payload2),
	TP_FIELDS(
		ctf_string(name, name)
		ctf_integer(long, long_payload1, payload1)
		ctf_integer(long, long_payload2, payload2)
	)
)

TRACEPOINT_EVENT(lttng_ust_java, string_event,
	TP_ARGS(const char *, name, const char *, payload),
	TP_FIELDS(
		ctf_string(name, name)
		ctf_string(string_payload, payload)
	)
)

#endif /* _TRACEPOINT_LTTNG_UST_JAVA_H */

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./lttng_ust_java.h"

/* This part must be outside protection */
#include <lttng/tracepoint-event.h>
