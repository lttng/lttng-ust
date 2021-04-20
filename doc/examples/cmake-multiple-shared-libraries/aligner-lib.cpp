/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2016 Sebastien Boisvert <sboisvert@gydle.com>
 */

#define LTTNG_UST_TRACEPOINT_DEFINE

#include "aligner-lib.h"
#include "tracepoint-provider.h"

void align_query(const std::string &query_name)
{
	tracepoint(gydle_om, align_query, query_name.c_str());

	/* Do the actual alignment */
	/* ... */
}
