/*
 * Copyright (C) 2009     Steven Rostedt <srostedt@redhat.com>
 * Copyright (C) 2010     Nils Carlson <nils.carlson@ericsson.com>
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
 *
 */

/*
 * This whole file is currently a dummy, mapping a TRACE_EVENT
 * to a printf
 */

#include <stdio.h>

/*
 * Stage 1. Create a struct and a printf calling function
 * that is connected to the tracepoint at load time.
 */
#undef TRACE_EVENT
#define TRACE_EVENT(name, proto, args, tstruct, assign, print)		\
	DECLARE_TRACE_EVENT_CLASS(name,					\
				  PARAMS(proto),			\
				  PARAMS(args),				\
				  PARAMS(tstruct),			\
				  PARAMS(assign),			\
				  PARAMS(print));			\
	DEFINE_TRACE_EVENT(name, name, PARAMS(proto), PARAMS(args));

#undef __field
#define __field(type, item)		type	item;

#undef TP_STRUCT__entry
#define TP_STRUCT__entry(args...) args

#undef TP_printf
#define TP_printf(fmt, args...) fmt "\n", args

#undef TP_fast_assign
#define TP_fast_assign(args...) args

#undef DEFINE_TRACE_EVENT
#define DEFINE_TRACE_EVENT(template, name, proto, args)


#undef DECLARE_TRACE_EVENT_CLASS
#define DECLARE_TRACE_EVENT_CLASS(name, proto, args, tstruct, assign, print)	\
	struct trace_raw_##name {					\
		tstruct							\
	};								\
	static void trace_printf_##name(void *dummy, proto)		\
	{								\
		struct trace_raw_##name entry_struct, *__entry;		\
		__entry = &entry_struct;				\
		{ assign };					\
									\
		printf(print);						\
	}								\
	static inline int register_event_##name(void *data)		\
	{								\
		return register_tracepoint(name, trace_printf_##name, data); \
	}								\
	static inline int unregister_event_##name(void *data)		\
	{								\
		return unregister_tracepoint(name, trace_printf_##name, data); \
	}								\
	struct trace_event __event_##name = {				\
		__tpstrtab_##name,					\
		register_event_##name,					\
		unregister_event_##name					\
	};								\
	static struct trace_event * const __event_ptrs_##name		\
	__attribute__((used, section("__trace_events_ptrs"))) =		\
		&__event_##name;					\
									\
	static void __attribute__((constructor)) init_##name()		\
	{								\
		void *dummy = NULL;					\
		register_tracepoint(name, trace_printf_##name, dummy);	\
	}


#include TRACE_INCLUDE(TRACE_INCLUDE_FILE)
