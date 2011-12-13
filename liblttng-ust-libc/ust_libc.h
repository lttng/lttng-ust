#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER ust_libc

#if !defined(_TRACEPOINT_UST_LIBC_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_UST_LIBC_H

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

TRACEPOINT_EVENT(ust_libc, malloc,
	TP_ARGS(size_t, size, void *, ptr),
	TP_FIELDS(
		ctf_integer(size_t, size, size)
		ctf_integer_hex(unsigned long, ptr, (unsigned long) ptr)
	)
)

TRACEPOINT_EVENT(ust_libc, free,
	TP_ARGS(void *, ptr),
	TP_FIELDS(
		ctf_integer_hex(unsigned long, ptr, (unsigned long) ptr)
	)
)

#endif /* _TRACEPOINT_UST_LIBC_H */

#undef TRACEPOINT_INCLUDE_FILE
#define TRACEPOINT_INCLUDE_FILE ./ust_libc.h

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>

#ifdef __cplusplus 
}
#endif
