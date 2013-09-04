#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER ust_pthread

#if !defined(_TRACEPOINT_UST_PTHREAD_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_UST_PTHREAD_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Copyright (C) 2013  Mentor Graphics
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(ust_pthread, pthread_mutex_lock_req,
	TP_ARGS(pthread_mutex_t *, mutex),
	TP_FIELDS(
		ctf_integer_hex(void *, mutex, mutex)
	)
)

TRACEPOINT_EVENT(ust_pthread, pthread_mutex_lock_acq,
	TP_ARGS(pthread_mutex_t *, mutex, int, status),
	TP_FIELDS(
		ctf_integer_hex(void *, mutex, mutex)
		ctf_integer(int, status, status)
	)
)

TRACEPOINT_EVENT(ust_pthread, pthread_mutex_trylock,
	TP_ARGS(pthread_mutex_t *, mutex, int, status),
	TP_FIELDS(
		ctf_integer_hex(void *, mutex, mutex)
		ctf_integer(int, status, status)
	)
)

TRACEPOINT_EVENT(ust_pthread, pthread_mutex_unlock,
	TP_ARGS(pthread_mutex_t *, mutex, int, status),
	TP_FIELDS(
		ctf_integer_hex(void *, mutex, mutex)
		ctf_integer(int, status, status)
	)
)

#endif /* _TRACEPOINT_UST_PTHREAD_H */

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./ust_pthread.h"

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>

#ifdef __cplusplus
}
#endif
