/*
 * Copyright (c) 2011 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifdef TRACEPOINT_CREATE_PROBES

#define __tp_stringify1(x)	#x
#define __tp_stringify(x)	__tp_stringify1(x)

#undef TRACEPOINT_EVENT_INSTANCE
#define TRACEPOINT_EVENT_INSTANCE(_provider, _template, _name, _args)

#undef TRACEPOINT_EVENT
#define TRACEPOINT_EVENT(_provider, _name, _args, _fields)		\
	TRACEPOINT_EVENT_CLASS(_provider, _name, _TP_PARAMS(_args),	\
			_TP_PARAMS(_fields))				\
	TRACEPOINT_EVENT_INSTANCE(_provider, _name, _name,		\
			_TP_PARAMS(_args))

#define TRACEPOINT_INCLUDE	__tp_stringify(TRACEPOINT_INCLUDE_FILE)

#undef TRACEPOINT_CREATE_PROBES

#define TRACEPOINT_HEADER_MULTI_READ
#include TRACEPOINT_INCLUDE

#include <lttng/ust-tracepoint-event.h>

#undef TRACEPOINT_HEADER_MULTI_READ

#define TRACEPOINT_CREATE_PROBES

#endif /* TRACEPOINT_CREATE_PROBES */

#ifdef __cplusplus
}
#endif
