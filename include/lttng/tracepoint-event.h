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

#include TRACEPOINT_INCLUDE

#include <lttng/ust-tracepoint-event.h>

#undef TRACEPOINT_HEADER_MULTI_READ
#undef TRACEPOINT_INCLUDE

#define TRACEPOINT_CREATE_PROBES

/*
 * Put back definitions to the state they were when defined by
 * tracepoint.h.
 */
#undef LTTNG_UST_TP_ARGS
#define LTTNG_UST_TP_ARGS(...)       __VA_ARGS__

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
