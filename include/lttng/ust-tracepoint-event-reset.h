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

/* Define to "nothing" all macros used for TRACEPOINT_EVENT */

#undef TRACEPOINT_EVENT_CLASS
#define TRACEPOINT_EVENT_CLASS(_provider, _name, _args, _fields)

#undef TRACEPOINT_EVENT_INSTANCE
#define TRACEPOINT_EVENT_INSTANCE(_provider, _template, _name, _args)

#undef TP_ARGS
#define TP_ARGS(...)

#undef TP_FIELDS
#define TP_FIELDS(...)

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

#undef  TRACEPOINT_LOGLEVEL_ENUM
#define TRACEPOINT_LOGLEVEL_ENUM(...)

#undef TRACEPOINT_LOGLEVEL
#define TRACEPOINT_LOGLEVEL(provider, name, loglevel)
