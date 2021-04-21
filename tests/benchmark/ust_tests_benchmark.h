/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2013 Zifei Tong <soariez@gmail.com>
 */

#undef LTTNG_UST_TRACEPOINT_PROVIDER
#define LTTNG_UST_TRACEPOINT_PROVIDER ust_tests_benchmark

#if !defined(_TRACEPOINT_UST_TESTS_BENCHMARK_H) || defined(LTTNG_UST_TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_UST_TESTS_BENCHMARK_H

#include <lttng/tracepoint.h>

LTTNG_UST_TRACEPOINT_EVENT(ust_tests_benchmark, tpbench,
	LTTNG_UST_TP_ARGS(int, value),
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_integer(int, event, value)
	)
)

#endif /* _TRACEPOINT_UST_TESTS_BENCHMARK_H */

#undef LTTNG_UST_TRACEPOINT_INCLUDE
#define LTTNG_UST_TRACEPOINT_INCLUDE "./ust_tests_benchmark.h"

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>
