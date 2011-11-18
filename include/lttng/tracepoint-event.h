/*
 * Copyright (c) 2011 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * THIS MATERIAL IS PROVIDED AS IS, WITH ABSOLUTELY NO WARRANTY EXPRESSED
 * OR IMPLIED.  ANY USE IS AT YOUR OWN RISK.
 *
 * Permission is hereby granted to use or copy this program
 * for any purpose,  provided the above notices are retained on all copies.
 * Permission to modify the code and to distribute modified code is granted,
 * provided the above notices are retained, and a notice that the code was
 * modified is included with the above copyright notice.
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifdef TRACEPOINT_CREATE_PROBES

#define __tp_stringify1(x)	#x
#define __tp_stringify(x)	__tp_stringify1(x)

#undef TRACEPOINT_EVENT_INSTANCE
#define TRACEPOINT_EVENT_INSTANCE(_provider, _template, _name, _args)	\
	_DEFINE_TRACEPOINT(provider, name)

#undef TRACEPOINT_EVENT
#define TRACEPOINT_EVENT(_provider, _name, _args, _fields)		\
	TRACEPOINT_EVENT_INSTANCE(_provider, _name, _name, _TP_PARAMS(_args))

#define TRACEPOINT_INCLUDE	__tp_stringify(TRACEPOINT_INCLUDE_FILE)

#undef TRACEPOINT_CREATE_PROBES

#define TRACEPOINT_HEADER_MULTI_READ
#include TRACEPOINT_INCLUDE
#undef TRACEPOINT_HEADER_MULTI_READ

#define TRACEPOINT_CREATE_PROBES

#endif /* TRACEPOINT_CREATE_PROBES */

#ifdef __cplusplus
}
#endif
