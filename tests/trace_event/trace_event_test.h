/* Copyright (C) 2010 Nils Carlson <nils.carlson@ericsson.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM trace_event_test

#if !defined(_TRACE_EVENT_TEST_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_EVENT_TEST_H

#include <ust/tracepoint.h>

TRACE_EVENT(test,

	TP_PROTO(unsigned long time, unsigned long count),

	TP_ARGS(time, count),

	TP_STRUCT__entry(
		__field(	unsigned long,	time	)
		__field(	unsigned long,	count	)
	),

	TP_fast_assign(
		__entry->time = time;
		__entry->count = count;
	),

	TP_printf("time=%lu count=%lu", __entry->time, __entry->count)
);

#endif /* _TRACE_EVENT_TEST_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE trace_event_test
#include <ust/define_trace.h>
