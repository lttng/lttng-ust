/*
 * Copyright (C) 2016  Sebastien Boisvert <sboisvert@gydle.com>
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

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER gydle_om

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "tracepoint-provider.h"

#if !defined(MY_TRACEPOINT_PROVIDER_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define MY_TRACEPOINT_PROVIDER_H

#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(
	TRACEPOINT_PROVIDER,
	align_query,
	TP_ARGS(
		const char *, query_name
	),
	TP_FIELDS(
		ctf_string(query_name, query_name)
	)
)

TRACEPOINT_EVENT(
	TRACEPOINT_PROVIDER,
	test_alignment,
	TP_ARGS(
		const char *, alignment
	),
	TP_FIELDS(
		ctf_string(alignment, alignment)
	)
)

#endif /* MY_TRACEPOINT_PROVIDER_H */

#include <lttng/tracepoint-event.h>
