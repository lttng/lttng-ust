#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER lttng_ust_java

#if !defined(_TRACEPOINT_LTTNG_UST_JAVA_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_LTTNG_UST_JAVA_H

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

TRACEPOINT_EVENT(lttng_ust_java, string,
	TP_ARGS(const char *, name, const char *, args),
	TP_FIELDS(
		ctf_string(name, name)
		ctf_string(args, args)
	)
)

#endif /* _TRACEPOINT_LTTNG_UST_JAVA_H */

#undef TRACEPOINT_INCLUDE_FILE
#define TRACEPOINT_INCLUDE_FILE ./lttng_ust_java

/* This part must be outside protection */
#include <lttng/tracepoint-event.h>
