#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER ust_tests_demo

#if !defined(_TRACEPOINT_UST_TESTS_DEMO_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_UST_TESTS_DEMO_H

#ifdef __cplusplus
extern "C" {
#endif

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

TRACEPOINT_EVENT(ust_tests_demo, loop,
	TP_ARGS(int, anint, int, netint, long *, values,
		 char *, text, size_t, textlen,
		 double, doublearg, float, floatarg),
	TP_FIELDS(
		ctf_integer(int, intfield, anint)
		ctf_integer_hex(int, intfield2, anint)
		ctf_integer(long, longfield, anint)
		ctf_integer_network(int, netintfield, netint)
		ctf_integer_network_hex(int, netintfieldhex, netint)
		ctf_array(long, arrfield1, values, 3)
		ctf_array_text(char, arrfield2, text, 10)
		ctf_sequence(char, seqfield1, text,
			     size_t, textlen)
		ctf_sequence_text(char, seqfield2, text,
			     size_t, textlen)
		ctf_string(stringfield, text)
		ctf_float(float, floatfield, floatarg)
		ctf_float(double, doublefield, doublearg)
	)
)

TRACEPOINT_EVENT(ust_tests_demo, starting,
	TP_ARGS(int, value),
	TP_FIELDS(
		ctf_integer(int, value, value)
	)
)

TRACEPOINT_EVENT(ust_tests_demo, done,
	TP_ARGS(int, value),
	TP_FIELDS(
		ctf_integer(int, value, value)
	)
)

#endif /* _TRACEPOINT_UST_TESTS_DEMO_H */

#undef TRACEPOINT_INCLUDE_PATH
#define TRACEPOINT_INCLUDE_PATH .
#undef TRACEPOINT_INCLUDE_FILE
#define TRACEPOINT_INCLUDE_FILE ust_tests_demo

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>

#ifdef __cplusplus 
}
#endif
