#undef TRACEPOINT_SYSTEM
#define TRACEPOINT_SYSTEM lttng_ust

#if !defined(_TRACEPOINT_LTTNG_UST_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_LTTNG_UST_H

/*
 * Copyright (C) 2011  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; version 2.1 of
 * the License.
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

#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(lttng_metadata,

	TP_PROTO(const char *str),

	TP_ARGS(str),

	/*
	 * Not exactly a string: more a sequence of bytes (dynamic
	 * array) without the length. This is a dummy anyway: we only
	 * use this declaration to generate an event metadata entry.
	 */
	TP_FIELDS(
		ctf_string(str, str)
	)
)

#undef TRACEPOINT_INCLUDE_PATH
#define TRACEPOINT_INCLUDE_PATH ./probes
#undef TRACEPOINT_INCLUDE_FILE
#define TRACEPOINT_INCLUDE_FILE lttng-probe-ust

#endif /* _TRACEPOINT_LTTNG_UST_H */

/* This part must be outside protection */
#include <lttng/tracepoint-event.h>
