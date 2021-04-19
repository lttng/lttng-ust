/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2013 Zifei Tong <soariez@gmail.com>
 */

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER ust_tests_benchmark

#if !defined(_TRACEPOINT_UST_TESTS_BENCHMARK_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_UST_TESTS_BENCHMARK_H

#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(ust_tests_benchmark, tpbench,
	LTTNG_UST_TP_ARGS(int, value),
	TP_FIELDS(
		ctf_integer(int, event, value)
	)
)

#endif /* _TRACEPOINT_UST_TESTS_BENCHMARK_H */

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./ust_tests_benchmark.h"

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>
