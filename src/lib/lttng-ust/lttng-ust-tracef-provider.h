/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2011-2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#undef LTTNG_UST_TRACEPOINT_PROVIDER
#define LTTNG_UST_TRACEPOINT_PROVIDER lttng_ust_tracef

#if !defined(_TRACEPOINT_LTTNG_UST_TRACEF_PROVIDER_H) || defined(LTTNG_UST_TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_LTTNG_UST_TRACEF_PROVIDER_H

#include <lttng/tp/lttng-ust-tracef.h>

#endif /* _TRACEPOINT_LTTNG_UST_TRACEF_PROVIDER_H */

#define TP_IP_PARAM ip	/* IP context received as parameter */
#undef LTTNG_UST_TRACEPOINT_INCLUDE
#define LTTNG_UST_TRACEPOINT_INCLUDE "./tp/lttng-ust-tracef.h"

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>
