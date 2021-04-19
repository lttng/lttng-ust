/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2011-2013 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER lttng_ust_cyg_profile_fast

#if !defined(_TRACEPOINT_LTTNG_UST_CYG_PROFILE_FAST_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_LTTNG_UST_CYG_PROFILE_FAST_H

#ifdef __cplusplus
extern "C" {
#endif

#include <lttng/tracepoint.h>

LTTNG_UST_TRACEPOINT_EVENT(lttng_ust_cyg_profile_fast, func_entry,
	LTTNG_UST_TP_ARGS(void *, func_addr),
	LTTNG_UST_TP_FIELDS(
		ctf_integer_hex(unsigned long, addr,
			(unsigned long) func_addr)
	)
)

TRACEPOINT_LOGLEVEL(lttng_ust_cyg_profile_fast, func_entry,
	TRACE_DEBUG_FUNCTION)

LTTNG_UST_TRACEPOINT_EVENT(lttng_ust_cyg_profile_fast, func_exit,
	LTTNG_UST_TP_ARGS(void *, func_addr),
	LTTNG_UST_TP_FIELDS(
		ctf_unused(func_addr)
	)
)

TRACEPOINT_LOGLEVEL(lttng_ust_cyg_profile_fast, func_exit,
	TRACE_DEBUG_FUNCTION)

#endif /* _TRACEPOINT_LTTNG_UST_CYG_PROFILE_FAST_H */

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./lttng-ust-cyg-profile-fast.h"

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>

#ifdef __cplusplus
}
#endif
