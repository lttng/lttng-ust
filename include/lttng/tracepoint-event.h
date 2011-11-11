/*
 * Copyright (C) 2009     Steven Rostedt <srostedt@redhat.com>
 * Copyright (C) 2011     Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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
 *
 * Trace files that want to automate creationg of all tracepoints defined
 * in their file should include this file. The following are macros that the
 * trace file may define:
 *
 * TRACEPOINT_PROVIDER defines the provider the tracepoint is for:
 *     < [com_company_]project_[component_] >
 *
 * TRACEPOINT_INCLUDE_FILE if the file name is something other than
 *     TRACEPOINT_PROVIDER.h. This macro may be defined to tell
 *     define_trace.h what file to include.  Note, leave off the ".h".
 *
 * TRACEPOINT_INCLUDE_PATH if the path is something other than within
 *     the system's include/tracepoint/ path, then this macro can define
 *     the path to use. This path is relative to tracepoint-event.h, or
 *     to the include search path. Trick: Use a
 *       #define TRACEPOINT_INCLUDE_PATH .
 *     combined with -Ipath_to_header as compiler argument to allow
 *     searching for a header within your project build tree.
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifdef TRACEPOINT_CREATE_PROBES

/* Prevent recursion */
#undef TRACEPOINT_CREATE_PROBES

#ifndef __tp_stringify
#define __tp_stringify_1(x...)	#x
#define __tp_stringify(x...)	__tp_stringify_1(x)
#endif

#undef TRACEPOINT_EVENT
#define TRACEPOINT_EVENT(provider, name, proto, args, fields)		\
	_DEFINE_TRACEPOINT(provider, name)

#undef TRACEPOINT_EVENT_INSTANCE
#define TRACEPOINT_EVENT_INSTANCE(provider, template, name, proto, args)	\
	_DEFINE_TRACEPOINT(provider, name)

#undef TRACEPOINT_EVENT_NOARGS
#define TRACEPOINT_EVENT_NOARGS(provider, name, fields)			\
	_DEFINE_TRACEPOINT(provider, name)

#undef TRACEPOINT_EVENT_INSTANCE_NOARGS
#define TRACEPOINT_EVENT_INSTANCE_NOARGS(provider, template, name)	\
	_DEFINE_TRACEPOINT(provider, name)

#undef TRACEPOINT_INCLUDE
#undef __TRACEPOINT_INCLUDE

#ifndef TRACEPOINT_INCLUDE_FILE
# define TRACEPOINT_INCLUDE_FILE TRACEPOINT_PROVIDER
# define UNDEF_TRACEPOINT_INCLUDE_FILE
#endif

#ifndef TRACEPOINT_INCLUDE_PATH
# define __TRACEPOINT_INCLUDE(provider) <tracepoint/provider.h>
# define UNDEF_TRACEPOINT_INCLUDE_PATH
#else
# define __TRACEPOINT_INCLUDE(provider)				\
	__tp_stringify(TRACEPOINT_INCLUDE_PATH/provider.h)
#endif

# define TRACEPOINT_INCLUDE(provider) __TRACEPOINT_INCLUDE(provider)

/* Let the trace headers be reread */
#define TRACEPOINT_HEADER_MULTI_READ

#include TRACEPOINT_INCLUDE(TRACEPOINT_INCLUDE_FILE)

#include <lttng/ust-tracepoint-event.h>

#undef TRACEPOINT_EVENT
#undef TRACEPOINT_EVENT_CLASS
#undef TRACEPOINT_EVENT_INSTANCE
#undef TRACEPOINT_EVENT_NOARGS
#undef TRACEPOINT_EVENT_CLASS_NOARGS
#undef TRACEPOINT_EVENT_INSTANCE_NOARGS
#undef TRACEPOINT_HEADER_MULTI_READ

/* Only undef what we defined in this file */
#ifdef UNDEF_TRACEPOINT_INCLUDE_FILE
# undef TRACEPOINT_INCLUDE_FILE
# undef UNDEF_TRACEPOINT_INCLUDE_FILE
#endif

#ifdef UNDEF_TRACEPOINT_INCLUDE_PATH
# undef TRACEPOINT_INCLUDE_PATH
# undef UNDEF_TRACEPOINT_INCLUDE_PATH
#endif

/* We may be processing more files */
#define TRACEPOINT_CREATE_PROBES

#endif /* TRACEPOINT_CREATE_PROBES */

#ifdef __cplusplus 
}
#endif
