#undef TRACE_SYSTEM
#define TRACE_SYSTEM trace_event_test

#if !defined(_TRACEPOINT_EVENT_TEST_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACEPOINT_EVENT_TEST_H

/*
 * Copyright (C) 2010 Nils Carlson <nils.carlson@ericsson.com>
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <ust/tracepoint.h>

TRACEPOINT_EVENT(test,

	TP_PROTO(unsigned long time, unsigned long count),

	TP_VARS(time, count),

	TP_FIELDS(
		tp_field(unsigned long, time, time)
		tp_field(unsigned long, count, count)
	)
);

#endif /* _TRACEPOINT_EVENT_TEST_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE trace_event_test
#include <ust/tracepoint_event.h>
