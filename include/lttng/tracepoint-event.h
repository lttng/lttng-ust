/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

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


#undef TRACEPOINT_CREATE_PROBES

#define TRACEPOINT_HEADER_MULTI_READ

/*
 * LTTng-UST 2.0 expects TRACEPOINT_INCLUDE_FILE, but this approach has
 * the unwanted side-effect of expanding any macro name found within
 * TRACEPOINT_INCLUDE_FILE.
 *
 * Starting from LTTng-UST 2.1, we expect the TRACEPOINT_INCLUDE to be
 * defined by probes as a string. We still check for
 * TRACEPOINT_INCLUDE_FILE for API backward compatibility.
 */
#ifdef TRACEPOINT_INCLUDE_FILE
#define TRACEPOINT_INCLUDE	__tp_stringify(TRACEPOINT_INCLUDE_FILE)
#endif

#include TRACEPOINT_INCLUDE

#include <lttng/ust-tracepoint-event.h>

#undef TRACEPOINT_HEADER_MULTI_READ
#undef TRACEPOINT_INCLUDE_FILE
#undef TRACEPOINT_INCLUDE

#define TRACEPOINT_CREATE_PROBES

/*
 * Put back definitions to the state they were when defined by
 * tracepoint.h.
 */
#undef TP_ARGS
#define TP_ARGS(...)       __VA_ARGS__

#undef TRACEPOINT_EVENT
#define TRACEPOINT_EVENT(provider, name, args, fields)			\
	_DECLARE_TRACEPOINT(provider, name, _TP_PARAMS(args))		\
	_DEFINE_TRACEPOINT(provider, name, _TP_PARAMS(args))

#undef TRACEPOINT_EVENT_CLASS
#define TRACEPOINT_EVENT_CLASS(provider, name, args, fields)

#undef TRACEPOINT_EVENT_INSTANCE
#define TRACEPOINT_EVENT_INSTANCE(provider, _template, name, args)	\
	_DECLARE_TRACEPOINT(provider, name, _TP_PARAMS(args))		\
	_DEFINE_TRACEPOINT(provider, name, _TP_PARAMS(args))

#undef TRACEPOINT_LOGLEVEL
#define TRACEPOINT_LOGLEVEL(provider, name, loglevel)

#undef TRACEPOINT_MODEL_EMF_URI
#define TRACEPOINT_MODEL_EMF_URI(provider, name, uri)

#endif /* TRACEPOINT_CREATE_PROBES */
