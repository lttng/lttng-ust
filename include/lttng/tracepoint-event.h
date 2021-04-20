/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include <lttng/ust-api-compat.h>


#if LTTNG_UST_COMPAT_API(0)
# if defined(TRACEPOINT_CREATE_PROBES) && !defined(LTTNG_UST_TRACEPOINT_CREATE_PROBES)
#  define LTTNG_UST_TRACEPOINT_CREATE_PROBES
# endif
#endif /* #if LTTNG_UST_COMPAT_API(0) */

#ifdef LTTNG_UST_TRACEPOINT_CREATE_PROBES

#define __tp_stringify1(x)	#x
#define __tp_stringify(x)	__tp_stringify1(x)

#undef LTTNG_UST_TRACEPOINT_EVENT_INSTANCE
#define LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(_provider, _template, _name, _args)

#undef LTTNG_UST_TRACEPOINT_EVENT
#define LTTNG_UST_TRACEPOINT_EVENT(_provider, _name, _args, _fields)		\
	LTTNG_UST_TRACEPOINT_EVENT_CLASS(_provider, _name, LTTNG_UST__TP_PARAMS(_args),	\
			LTTNG_UST__TP_PARAMS(_fields))				\
	LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(_provider, _name, _name,		\
			LTTNG_UST__TP_PARAMS(_args))


#undef LTTNG_UST_TRACEPOINT_CREATE_PROBES
#if LTTNG_UST_COMPAT_API(0)
#undef TRACEPOINT_CREATE_PROBES
#endif

#define LTTNG_UST_TRACEPOINT_HEADER_MULTI_READ
#if LTTNG_UST_COMPAT_API(0)
#define TRACEPOINT_HEADER_MULTI_READ
#endif

#if LTTNG_UST_COMPAT_API(0)
# if defined(TRACEPOINT_INCLUDE) && !defined(LTTNG_UST_TRACEPOINT_INCLUDE)
#  define LTTNG_UST_TRACEPOINT_INCLUDE TRACEPOINT_INCLUDE
# endif
#endif /* #if LTTNG_UST_COMPAT_API(0) */

#if LTTNG_UST_COMPAT_API(0)
# if defined(TRACEPOINT_PROVIDER) && !defined(LTTNG_UST_TRACEPOINT_PROVIDER)
#  define LTTNG_UST_TRACEPOINT_PROVIDER TRACEPOINT_PROVIDER
# endif
#endif /* #if LTTNG_UST_COMPAT_API(0) */

#include LTTNG_UST_TRACEPOINT_INCLUDE

#include <lttng/ust-tracepoint-event.h>

#undef LTTNG_UST_TRACEPOINT_HEADER_MULTI_READ
#if LTTNG_UST_COMPAT_API(0)
#undef TRACEPOINT_HEADER_MULTI_READ
#endif

#undef LTTNG_UST_TRACEPOINT_INCLUDE
#if LTTNG_UST_COMPAT_API(0)
# undef TRACEPOINT_INCLUDE
#endif

#define LTTNG_UST_TRACEPOINT_CREATE_PROBES

/*
 * Put back definitions to the state they were when defined by
 * tracepoint.h.
 */
#undef LTTNG_UST_TP_ARGS
#define LTTNG_UST_TP_ARGS(...)       __VA_ARGS__

#undef LTTNG_UST_TRACEPOINT_EVENT
#define LTTNG_UST_TRACEPOINT_EVENT(provider, name, args, fields)			\
	LTTNG_UST__DECLARE_TRACEPOINT(provider, name, LTTNG_UST__TP_PARAMS(args))		\
	LTTNG_UST__DEFINE_TRACEPOINT(provider, name, LTTNG_UST__TP_PARAMS(args))

#undef LTTNG_UST_TRACEPOINT_EVENT_CLASS
#define LTTNG_UST_TRACEPOINT_EVENT_CLASS(provider, name, args, fields)

#undef LTTNG_UST_TRACEPOINT_EVENT_INSTANCE
#define LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(provider, _template, name, args)	\
	LTTNG_UST__DECLARE_TRACEPOINT(provider, name, LTTNG_UST__TP_PARAMS(args))		\
	LTTNG_UST__DEFINE_TRACEPOINT(provider, name, LTTNG_UST__TP_PARAMS(args))

#undef LTTNG_UST_TRACEPOINT_LOGLEVEL
#define LTTNG_UST_TRACEPOINT_LOGLEVEL(provider, name, loglevel)

#undef LTTNG_UST_TRACEPOINT_MODEL_EMF_URI
#define LTTNG_UST_TRACEPOINT_MODEL_EMF_URI(provider, name, uri)

#endif /* LTTNG_UST_TRACEPOINT_CREATE_PROBES */
