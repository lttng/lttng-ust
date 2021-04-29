/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER ust_tests_hello_many

#if !defined(_TRACEPOINT_UST_TESTS_HELLO_MANY_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_UST_TESTS_HELLO_MANY_H

#include <lttng/tracepoint.h>
#include <stdbool.h>

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple1,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple2,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple3,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple4,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple5,
	TP_ARGS(),
	TP_FIELDS()
)


TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple6,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple7,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple8,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple9,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple10,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple11,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple12,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple13,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple14,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple15,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple16,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple17,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple18,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple19,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple20,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple21,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple22,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple23,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple24,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple25,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple26,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple27,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple28,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple29,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple30,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple31,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple32,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple33,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple34,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple35,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple36,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple37,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple38,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple39,
	TP_ARGS(),
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_hello_many, tptest_simple40,
	TP_ARGS(),
	TP_FIELDS()
)

#endif /* _TRACEPOINT_UST_TESTS_HELLO_MANY_H */

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./ust_tests_hello_many.h"

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>
