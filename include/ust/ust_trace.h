/*
 * Copyright (C) 2009     Steven Rostedt <srostedt@redhat.com>
 * Copyright (C) 2010     Nils Carlson <nils.carlson@ericsson.com>
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
 */

/*
 * This whole file is currently a dummy.
 */

#include <stdio.h>

#undef TRACEPOINT_EVENT
#define TRACEPOINT_EVENT(name, proto, args, fields)			\
	TRACEPOINT_EVENT_CLASS(name,					\
			TP_PARAMS(proto),				\
			TP_PARAMS(args),				\
			TP_PARAMS(fields));				\
	TRACEPOINT_EVENT_INSTANCE(name, name, TP_PARAMS(proto),		\
			TP_PARAMS(args));

#undef TRACEPOINT_EVENT_NOARGS
#define TRACEPOINT_EVENT_NOARGS(name, fields)				\
	TRACEPOINT_EVENT_CLASS_NOARGS(name,				\
			TP_PARAMS(fields));				\
	TRACEPOINT_EVENT_INSTANCE_NOARGS(name, name);

#undef tp_field
#define tp_field(type, item, src)	type	item;

#undef TP_FIELDS
#define TP_FIELDS(args...) args

#undef TRACEPOINT_EVENT_INSTANCE
#define TRACEPOINT_EVENT_INSTANCE(template, name, proto, args)

#undef TRACEPOINT_EVENT_INSTANCE_NOARGS
#define TRACEPOINT_EVENT_INSTANCE_NOARGS(template, name)

#undef TRACEPOINT_EVENT_CLASS
#define TRACEPOINT_EVENT_CLASS(name, proto, args, fields)		\
	struct trace_raw_##name {					\
		fields							\
	};								\
	static void trace_printf_##name(void *dummy, proto)		\
	{								\
	}								\
	struct trace_event __event_##name = {				\
		__tpstrtab_##name,					\
	};								\
	static struct trace_event * const __event_ptrs_##name		\
	__attribute__((used, section("__trace_events_ptrs"))) =		\
		&__event_##name;					\
									\
	static void __attribute__((constructor)) init_##name()		\
	{								\
		void *dummy = NULL;					\
		__register_tracepoint(name, trace_printf_##name, dummy);\
	}

#undef TRACEPOINT_EVENT_CLASS_NOARGS
#define TRACEPOINT_EVENT_CLASS_NOARGS(name, fields)			\
	struct trace_raw_##name {					\
		fields							\
	};								\
	static void trace_printf_##name(void *dummy)			\
	{								\
	}								\
	struct trace_event __event_##name = {				\
		__tpstrtab_##name,					\
	};								\
	static struct trace_event * const __event_ptrs_##name		\
	__attribute__((used, section("__trace_events_ptrs"))) =		\
		&__event_##name;					\
									\
	static void __attribute__((constructor)) init_##name()		\
	{								\
		void *dummy = NULL;					\
		__register_tracepoint(name, trace_printf_##name, dummy);\
	}

#include TRACE_INCLUDE(TRACE_INCLUDE_FILE)
