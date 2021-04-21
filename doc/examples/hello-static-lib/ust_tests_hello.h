/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#undef LTTNG_UST_TRACEPOINT_PROVIDER
#define LTTNG_UST_TRACEPOINT_PROVIDER ust_tests_hello

#if !defined(_TRACEPOINT_UST_TESTS_HELLO_H) || defined(LTTNG_UST_TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_UST_TESTS_HELLO_H

#include <lttng/tracepoint.h>
#include <stddef.h>

LTTNG_UST_TRACEPOINT_EVENT(ust_tests_hello, tptest,
	LTTNG_UST_TP_ARGS(int, anint, int, netint, long *, values,
		 char *, text, size_t, textlen,
		 double, doublearg, float, floatarg),
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_integer(int, intfield, anint)
		lttng_ust_field_integer_hex(int, intfield2, anint)
		lttng_ust_field_integer(long, longfield, anint)
		lttng_ust_field_integer_network(int, netintfield, netint)
		lttng_ust_field_integer_network_hex(int, netintfieldhex, netint)
		lttng_ust_field_array(long, arrfield1, values, 3)
		lttng_ust_field_array_text(char, arrfield2, text, 10)
		lttng_ust_field_sequence(char, seqfield1, text,
			     size_t, textlen)
		lttng_ust_field_sequence_text(char, seqfield2, text,
			     size_t, textlen)
		lttng_ust_field_string(stringfield, text)
		lttng_ust_field_float(float, floatfield, floatarg)
		lttng_ust_field_float(double, doublefield, doublearg)
	)
)

LTTNG_UST_TRACEPOINT_EVENT(ust_tests_hello, tptest_sighandler,
	LTTNG_UST_TP_ARGS(),
	LTTNG_UST_TP_FIELDS()
)

#endif /* _TRACEPOINT_UST_TESTS_HELLO_H */

#undef LTTNG_UST_TRACEPOINT_INCLUDE
#define LTTNG_UST_TRACEPOINT_INCLUDE "./ust_tests_hello.h"

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>
