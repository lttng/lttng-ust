/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#undef LTTNG_UST_TRACEPOINT_PROVIDER
#define LTTNG_UST_TRACEPOINT_PROVIDER ust_tests_sameline

#if !defined(_TRACEPOINT_UST_TESTS_SAMELINE_H) || defined(LTTNG_UST_TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_UST_TESTS_SAMELINE_H

#include <lttng/tracepoint.h>

LTTNG_UST_TRACEPOINT_EVENT(ust_tests_sameline, event1,
	LTTNG_UST_TP_ARGS(),
	LTTNG_UST_TP_FIELDS()
)
LTTNG_UST_TRACEPOINT_LOGLEVEL(ust_tests_sameline, event1, TRACE_CRIT)

LTTNG_UST_TRACEPOINT_EVENT(ust_tests_sameline, event2,
	LTTNG_UST_TP_ARGS(),
	LTTNG_UST_TP_FIELDS()
)
LTTNG_UST_TRACEPOINT_LOGLEVEL(ust_tests_sameline, event2, TRACE_CRIT)

#endif /* _TRACEPOINT_UST_TESTS_SAMELINE_H */

#undef LTTNG_UST_TRACEPOINT_INCLUDE
#define LTTNG_UST_TRACEPOINT_INCLUDE "./ust_tests_sameline.h"

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>
