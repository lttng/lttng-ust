/*
 * lttng/ust-tracepoint-events-reset.h
 *
 * Copyright (C) 2010-2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Dual LGPL v2.1/GPL v2 license.
 */

/* Reset macros used within TRACEPOINT_EVENT to "nothing" */

#undef ctf_integer_ext
#define ctf_integer_ext(_type, _item, _src, _byte_order, _base)

#undef ctf_float
#define ctf_float(_type, _item, _src)

#undef ctf_array_encoded
#define ctf_array_encoded(_type, _item, _src, _length, _encoding)

#undef ctf_sequence_encoded
#define ctf_sequence_encoded(_type, _item, _src, _length_type, \
			_src_length, _encoding)

#undef ctf_string
#define ctf_string(_item, _src)

#undef TP_PROTO
#define TP_PROTO(args...)

#undef TP_ARGS
#define TP_ARGS(args...)

#undef TP_FIELDS
#define TP_FIELDS(args...)

#undef TRACEPOINT_EVENT_CLASS
#define TRACEPOINT_EVENT_CLASS(_provider, _name, _proto, _args, _fields)

#undef TRACEPOINT_EVENT_CLASS_NOARGS
#define TRACEPOINT_EVENT_CLASS_NOARGS(_provider, _name, _fields)

#undef TRACEPOINT_EVENT_INSTANCE
#define TRACEPOINT_EVENT_INSTANCE(_provider, _template, _name, _proto, _args)

#undef TRACEPOINT_EVENT_INSTANCE_NOARGS
#define TRACEPOINT_EVENT_INSTANCE_NOARGS(_provider, _template, _name)
