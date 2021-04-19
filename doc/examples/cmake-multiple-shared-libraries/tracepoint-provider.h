/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2016 Sebastien Boisvert <sboisvert@gydle.com>
 */

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER gydle_om

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "tracepoint-provider.h"

#if !defined(MY_TRACEPOINT_PROVIDER_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define MY_TRACEPOINT_PROVIDER_H

#include <lttng/tracepoint.h>

LTTNG_UST_TRACEPOINT_EVENT(
	TRACEPOINT_PROVIDER,
	align_query,
	LTTNG_UST_TP_ARGS(
		const char *, query_name
	),
	LTTNG_UST_TP_FIELDS(
		ctf_string(query_name, query_name)
	)
)

LTTNG_UST_TRACEPOINT_EVENT(
	TRACEPOINT_PROVIDER,
	test_alignment,
	LTTNG_UST_TP_ARGS(
		const char *, alignment
	),
	LTTNG_UST_TP_FIELDS(
		ctf_string(alignment, alignment)
	)
)

#endif /* MY_TRACEPOINT_PROVIDER_H */

#include <lttng/tracepoint-event.h>
