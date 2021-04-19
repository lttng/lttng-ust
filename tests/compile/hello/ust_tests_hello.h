/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER ust_tests_hello

#if !defined(_TRACEPOINT_UST_TESTS_HELLO_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_UST_TESTS_HELLO_H

#include <lttng/tracepoint.h>
#include <stdbool.h>
#include <stddef.h>

TRACEPOINT_EVENT(ust_tests_hello, tptest,
	LTTNG_UST_TP_ARGS(int, anint, int, netint, long *, values,
		char *, text, size_t, textlen,
		double, doublearg, float, floatarg,
		bool, boolarg),
	TP_FIELDS(
		ctf_integer(int, intfield, anint)
		ctf_integer_hex(int, intfield2, anint)
		ctf_integer(long, longfield, anint)
		ctf_integer_network(int, netintfield, netint)
		ctf_integer_network_hex(int, netintfieldhex, netint)
		ctf_array_nowrite(long, arrfield1z, values, 3)
		ctf_array(long, blah, values, 3)
		ctf_array(long, arrfield1, values, 3)
		ctf_array_hex(long, arrfield1_hex, values, 3)
		ctf_array_network(long, arrfield1_network, values, 3)
		ctf_array_network_hex(long, arrfield1_network_hex, values, 3)
		ctf_array_text(char, arrfield2, text, 10)
		ctf_sequence(char, seqfield1, text,
			     size_t, textlen)
		ctf_sequence_nowrite(char, seqfield1z, text,
			     size_t, textlen)
		ctf_sequence_hex(char, seqfield1_hex, text,
			     size_t, textlen)
		ctf_sequence_text(char, seqfield2, text,
			     size_t, textlen)
		ctf_sequence_network(long, seqfield_network_3, values,
			     size_t, 3)
		ctf_string(stringfield, text)
		ctf_float(float, floatfield, floatarg)
		ctf_float(double, doublefield, doublearg)
		ctf_integer(bool, boolfield, boolarg)
		ctf_integer_nowrite(int, filterfield, anint)
	)
)

TRACEPOINT_EVENT(ust_tests_hello, tptest_sighandler,
	LTTNG_UST_TP_ARGS(),
	TP_FIELDS()
)

#endif /* _TRACEPOINT_UST_TESTS_HELLO_H */

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./ust_tests_hello.h"

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>
