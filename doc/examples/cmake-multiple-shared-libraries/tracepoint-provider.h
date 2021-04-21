/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2016 Sebastien Boisvert <sboisvert@gydle.com>
 */

#undef LTTNG_UST_TRACEPOINT_PROVIDER
#define LTTNG_UST_TRACEPOINT_PROVIDER gydle_om

#undef LTTNG_UST_TRACEPOINT_INCLUDE
#define LTTNG_UST_TRACEPOINT_INCLUDE "tracepoint-provider.h"

#if !defined(MY_TRACEPOINT_PROVIDER_H) || defined(LTTNG_UST_TRACEPOINT_HEADER_MULTI_READ)
#define MY_TRACEPOINT_PROVIDER_H

#include <lttng/tracepoint.h>

LTTNG_UST_TRACEPOINT_EVENT(
	LTTNG_UST_TRACEPOINT_PROVIDER,
	align_query,
	LTTNG_UST_TP_ARGS(
		const char *, query_name
	),
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_string(query_name, query_name)
	)
)

LTTNG_UST_TRACEPOINT_EVENT(
	LTTNG_UST_TRACEPOINT_PROVIDER,
	test_alignment,
	LTTNG_UST_TP_ARGS(
		const char *, alignment
	),
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_string(alignment, alignment)
	)
)

#endif /* MY_TRACEPOINT_PROVIDER_H */

#include <lttng/tracepoint-event.h>
