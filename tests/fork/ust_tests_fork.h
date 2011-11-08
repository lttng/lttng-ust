#undef TRACEPOINT_SYSTEM
#define TRACEPOINT_SYSTEM ust_tests_fork

#if !defined(_TRACEPOINT_UST_TESTS_FORK_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_UST_TESTS_FORK_H

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
#include <sys/types.h>

TRACEPOINT_EVENT_NOARGS(ust_tests_fork, before_fork,
	TP_FIELDS()
)

TRACEPOINT_EVENT(ust_tests_fork, after_fork_child,
	TP_PROTO(pid_t pid),
	TP_ARGS(pid),
	TP_FIELDS(
		ctf_integer(pid_t, pid, pid)
	)
)

TRACEPOINT_EVENT_NOARGS(ust_tests_fork, after_fork_parent,
	TP_FIELDS()
)

TRACEPOINT_EVENT_NOARGS(ust_tests_fork, after_exec,
	TP_FIELDS()
)

#endif /* _TRACEPOINT_UST_TESTS_FORK_H */

#undef TRACEPOINT_INCLUDE_PATH
#define TRACEPOINT_INCLUDE_PATH .
#undef TRACEPOINT_INCLUDE_FILE
#define TRACEPOINT_INCLUDE_FILE ust_tests_fork

/* This part must be outside protection */
#include <lttng/tracepoint-event.h>
