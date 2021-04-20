/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER lttng_ust_java

#if !defined(_TRACEPOINT_LTTNG_UST_JAVA_H) || defined(LTTNG_UST_TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_LTTNG_UST_JAVA_H

#include <lttng/tracepoint.h>

LTTNG_UST_TRACEPOINT_EVENT(lttng_ust_java, int_event,
	LTTNG_UST_TP_ARGS(const char *, name, int, payload),
	LTTNG_UST_TP_FIELDS(
		ctf_string(name, name)
		ctf_integer(int, int_payload, payload)
	)
)

LTTNG_UST_TRACEPOINT_EVENT(lttng_ust_java, int_int_event,
	LTTNG_UST_TP_ARGS(const char *, name, int, payload1, int, payload2),
	LTTNG_UST_TP_FIELDS(
		ctf_string(name, name)
		ctf_integer(int, int_payload1, payload1)
		ctf_integer(int, int_payload2, payload2)
	)
)

LTTNG_UST_TRACEPOINT_EVENT(lttng_ust_java, long_event,
	LTTNG_UST_TP_ARGS(const char *, name, long, payload),
	LTTNG_UST_TP_FIELDS(
		ctf_string(name, name)
		ctf_integer(long, long_payload, payload)
	)
)

LTTNG_UST_TRACEPOINT_EVENT(lttng_ust_java, long_long_event,
	LTTNG_UST_TP_ARGS(const char *, name, long, payload1, long, payload2),
	LTTNG_UST_TP_FIELDS(
		ctf_string(name, name)
		ctf_integer(long, long_payload1, payload1)
		ctf_integer(long, long_payload2, payload2)
	)
)

LTTNG_UST_TRACEPOINT_EVENT(lttng_ust_java, string_event,
	LTTNG_UST_TP_ARGS(const char *, name, const char *, payload),
	LTTNG_UST_TP_FIELDS(
		ctf_string(name, name)
		ctf_string(string_payload, payload)
	)
)

#endif /* _TRACEPOINT_LTTNG_UST_JAVA_H */

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./lttng_ust_java.h"

/* This part must be outside protection */
#include <lttng/tracepoint-event.h>
