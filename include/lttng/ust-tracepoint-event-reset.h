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
