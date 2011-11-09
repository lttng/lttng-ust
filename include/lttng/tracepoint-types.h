#ifndef _LTTNG_TRACEPOINT_TYPES_H
#define _LTTNG_TRACEPOINT_TYPES_H

/*
 * Copyright (C) 2008-2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2009 Pierre-Marc Fournier
 * Copyright (C) 2009 Steven Rostedt <rostedt@goodmis.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 *
 * Heavily inspired from the Linux Kernel Markers.
 */

#ifdef __cplusplus
extern "C" {
#endif

struct tracepoint_probe {
	void *func;
	void *data;
};

struct tracepoint {
	const char *name;		/* Tracepoint name */
	char state;			/* State. */
	struct tracepoint_probe *probes;
};

#ifdef __cplusplus 
}
#endif

#endif /* _LTTNG_TRACEPOINT_TYPES_H */
