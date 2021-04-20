/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER ust_tests_demo

#if !defined(_TRACEPOINT_UST_TESTS_DEMO_H) || defined(LTTNG_UST_TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_UST_TESTS_DEMO_H

#include <lttng/tracepoint.h>

LTTNG_UST_TRACEPOINT_EVENT(ust_tests_demo, starting,
	LTTNG_UST_TP_ARGS(int, value),
	LTTNG_UST_TP_FIELDS(
		ctf_integer(int, value, value)
	)
)
LTTNG_UST_TRACEPOINT_LOGLEVEL(ust_tests_demo, starting, LTTNG_UST_TRACEPOINT_LOGLEVEL_CRIT)

/*
 * Dummy model information, just for example. TODO: we should check if
 * EMF model URI have some standard format we should follow.
 */
LTTNG_UST_TRACEPOINT_MODEL_EMF_URI(ust_tests_demo, starting,
	"http://example.com/path_to_model?q=ust_tests_demo:starting")

LTTNG_UST_TRACEPOINT_EVENT(ust_tests_demo, done,
	LTTNG_UST_TP_ARGS(int, value),
	LTTNG_UST_TP_FIELDS(
		ctf_integer(int, value, value)
	)
)
LTTNG_UST_TRACEPOINT_LOGLEVEL(ust_tests_demo, done, LTTNG_UST_TRACEPOINT_LOGLEVEL_CRIT)

LTTNG_UST_TRACEPOINT_MODEL_EMF_URI(ust_tests_demo, done,
	"http://example.com/path_to_model?q=ust_tests_demo:done")

#endif /* _TRACEPOINT_UST_TESTS_DEMO_H */

#undef LTTNG_UST_TRACEPOINT_INCLUDE
#define LTTNG_UST_TRACEPOINT_INCLUDE "./ust_tests_demo.h"

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>
