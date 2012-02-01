#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER ust_tests_demo3

#if !defined(_TRACEPOINT_UST_TESTS_DEMO3_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_UST_TESTS_DEMO3_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Copyright (C) 2011  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * THIS MATERIAL IS PROVIDED AS IS, WITH ABSOLUTELY NO WARRANTY EXPRESSED
 * OR IMPLIED.  ANY USE IS AT YOUR OWN RISK.
 *
 * Permission is hereby granted to use or copy this program
 * for any purpose,  provided the above notices are retained on all copies.
 * Permission to modify the code and to distribute modified code is granted,
 * provided the above notices are retained, and a notice that the code was
 * modified is included with the above copyright notice.
 */

#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(ust_tests_demo3, done,
	TP_ARGS(int, value),
	TP_FIELDS(
		ctf_integer(int, value, value)
	)
)
TRACEPOINT_LOGLEVEL(ust_tests_demo3, done, TRACE_WARNING)

#endif /* _TRACEPOINT_UST_TESTS_DEMO3_H */

#undef TRACEPOINT_INCLUDE_FILE
#define TRACEPOINT_INCLUDE_FILE ./ust_tests_demo3.h

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>

#ifdef __cplusplus 
}
#endif
