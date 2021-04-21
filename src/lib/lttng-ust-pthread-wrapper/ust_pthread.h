/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2013  Mentor Graphics
 */

#undef LTTNG_UST_TRACEPOINT_PROVIDER
#define LTTNG_UST_TRACEPOINT_PROVIDER lttng_ust_pthread

#if !defined(_TRACEPOINT_UST_PTHREAD_H) || defined(LTTNG_UST_TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_UST_PTHREAD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <lttng/tracepoint.h>

LTTNG_UST_TRACEPOINT_EVENT(lttng_ust_pthread, pthread_mutex_lock_req,
	LTTNG_UST_TP_ARGS(pthread_mutex_t *, mutex, void *, ip),
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_integer_hex(void *, mutex, mutex)
		ctf_unused(ip)
	)
)

LTTNG_UST_TRACEPOINT_EVENT(lttng_ust_pthread, pthread_mutex_lock_acq,
	LTTNG_UST_TP_ARGS(pthread_mutex_t *, mutex, int, status, void *, ip),
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_integer_hex(void *, mutex, mutex)
		lttng_ust_field_integer(int, status, status)
		ctf_unused(ip)
	)
)

LTTNG_UST_TRACEPOINT_EVENT(lttng_ust_pthread, pthread_mutex_trylock,
	LTTNG_UST_TP_ARGS(pthread_mutex_t *, mutex, int, status, void *, ip),
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_integer_hex(void *, mutex, mutex)
		lttng_ust_field_integer(int, status, status)
		ctf_unused(ip)
	)
)

LTTNG_UST_TRACEPOINT_EVENT(lttng_ust_pthread, pthread_mutex_unlock,
	LTTNG_UST_TP_ARGS(pthread_mutex_t *, mutex, int, status, void *, ip),
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_integer_hex(void *, mutex, mutex)
		lttng_ust_field_integer(int, status, status)
		ctf_unused(ip)
	)
)

#endif /* _TRACEPOINT_UST_PTHREAD_H */

#undef LTTNG_UST_TRACEPOINT_INCLUDE
#define LTTNG_UST_TRACEPOINT_INCLUDE "./ust_pthread.h"

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>

#ifdef __cplusplus
}
#endif
