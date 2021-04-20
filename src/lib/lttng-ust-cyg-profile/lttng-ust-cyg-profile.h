/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2011-2013 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER lttng_ust_cyg_profile

#if !defined(_TRACEPOINT_LTTNG_UST_CYG_PROFILE_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_LTTNG_UST_CYG_PROFILE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <lttng/tracepoint.h>

LTTNG_UST_TRACEPOINT_EVENT_CLASS(lttng_ust_cyg_profile, func_class,
	LTTNG_UST_TP_ARGS(void *, func_addr, void *, call_site),
	LTTNG_UST_TP_FIELDS(
		ctf_integer_hex(unsigned long, addr,
			(unsigned long) func_addr)
		ctf_integer_hex(unsigned long, call_site,
			(unsigned long) call_site)
	)
)

LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(lttng_ust_cyg_profile, func_class,
	func_entry,
	LTTNG_UST_TP_ARGS(void *, func_addr, void *, call_site)
)

LTTNG_UST_TRACEPOINT_LOGLEVEL(lttng_ust_cyg_profile, func_entry,
	LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_FUNCTION)

LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(lttng_ust_cyg_profile, func_class,
	func_exit,
	LTTNG_UST_TP_ARGS(void *, func_addr, void *, call_site)
)

LTTNG_UST_TRACEPOINT_LOGLEVEL(lttng_ust_cyg_profile, func_exit,
	LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_FUNCTION)

#endif /* _TRACEPOINT_LTTNG_UST_CYG_PROFILE_H */

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./lttng-ust-cyg-profile.h"

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>

#ifdef __cplusplus
}
#endif
