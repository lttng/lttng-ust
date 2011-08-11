#undef TRACEPOINT_SYSTEM
#define TRACEPOINT_SYSTEM ust_tests_hello

#if !defined(_TRACEPOINT_UST_TESTS_HELLO_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_UST_TESTS_HELLO_H

/*
 * Copyright (C) 2011  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
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

#include <ust/tracepoint.h>

TRACEPOINT_EVENT(ust_tests_hello_tptest,
			TP_PROTO(int anint, long *values),
			TP_ARGS(anint, values),
			TP_FIELDS(
				ctf_integer(int, intfield, anint)
				ctf_integer_hex(int, intfield2, anint)
				ctf_integer_network(int, intfield3, anint)
				ctf_integer_network_hex(int, intfield4, anint)
				ctf_array(long, arrfield1, values, 3)
			))

TRACEPOINT_EVENT_NOARGS(ust_tests_hello_tptest_sighandler,
			TP_FIELDS())

#endif /* _TRACEPOINT_TP_H */

#undef TRACEPOINT_INCLUDE_PATH
#define TRACEPOINT_INCLUDE_PATH .
#undef TRACEPOINT_INCLUDE_FILE
#define TRACEPOINT_INCLUDE_FILE ust_tests_hello

/* This part must be outside protection */
#include <ust/tracepoint-event.h>
