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
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/* Define to "nothing" all macros used for TRACEPOINT_EVENT */

#undef TRACEPOINT_EVENT_CLASS
#define TRACEPOINT_EVENT_CLASS(_provider, _name, _args, _fields)

#undef TRACEPOINT_EVENT_INSTANCE
#define TRACEPOINT_EVENT_INSTANCE(_provider, _template, _name, _args)

#undef TRACEPOINT_ENUM
#define TRACEPOINT_ENUM(_provider, _name, _values)

#undef TP_ARGS
#define TP_ARGS(...)

#undef TP_FIELDS
#define TP_FIELDS(...)

#undef  TRACEPOINT_LOGLEVEL_ENUM
#define TRACEPOINT_LOGLEVEL_ENUM(...)

#undef TRACEPOINT_LOGLEVEL
#define TRACEPOINT_LOGLEVEL(provider, name, loglevel)

#undef TRACEPOINT_MODEL_EMF_URI
#define TRACEPOINT_MODEL_EMF_URI(provider, name, uri)

#undef _ctf_integer_ext
#define _ctf_integer_ext(_type, _item, _src, _byte_order, _base, \
			_nowrite)

#undef _ctf_float
#define _ctf_float(_type, _item, _src, _nowrite)

#undef _ctf_array_encoded
#define _ctf_array_encoded(_type, _item, _src, _byte_order, _length, _encoding, \
			_nowrite, _elem_type_base)

#undef _ctf_sequence_encoded
#define _ctf_sequence_encoded(_type, _item, _src, _byte_order, _length_type, \
			_src_length, _encoding, _nowrite, _elem_type_base)

#undef _ctf_string
#define _ctf_string(_item, _src, _nowrite)

#undef _ctf_enum
#define _ctf_enum(_provider, _name, _type, _item, _src, _nowrite)

/* "write" */
#undef ctf_integer
#define ctf_integer(_type, _item, _src)

#undef ctf_integer_hex
#define ctf_integer_hex(_type, _item, _src)

#undef ctf_integer_network
#define ctf_integer_network(_type, _item, _src)

#undef ctf_integer_network_hex
#define ctf_integer_network_hex(_type, _item, _src)

#undef ctf_float
#define ctf_float(_type, _item, _src)

#undef ctf_array
#define ctf_array(_type, _item, _src, _length)

#undef ctf_array_hex
#define ctf_array_hex(_type, _item, _src, _length)

#undef ctf_array_network
#define ctf_array_network(_type, _item, _src, _length)

#undef ctf_array_network_hex
#define ctf_array_network_hex(_type, _item, _src, _length)

#undef ctf_array_text
#define ctf_array_text(_type, _item, _src, _length)

#undef ctf_sequence
#define ctf_sequence(_type, _item, _src, _length_type, _src_length)

#undef ctf_sequence_hex
#define ctf_sequence_hex(_type, _item, _src, _length_type, _src_length)

#undef ctf_sequence_network
#define ctf_sequence_network(_type, _item, _src, _length_type, _src_length)

#undef ctf_sequence_network_hex
#define ctf_sequence_network_hex(_type, _item, _src, _length_type, _src_length)

#undef ctf_sequence_text
#define ctf_sequence_text(_type, _item, _src, _length_type, _src_length)

#undef ctf_string
#define ctf_string(_item, _src)

#undef ctf_enum
#define ctf_enum(_provider, _name, _type, _item, _src)

/* "nowrite" */
#undef ctf_integer_nowrite
#define ctf_integer_nowrite(_type, _item, _src)

#undef ctf_float_nowrite
#define ctf_float_nowrite(_type, _item, _src)

#undef ctf_array_nowrite
#define ctf_array_nowrite(_type, _item, _src, _length)

#undef ctf_array_nowrite_hex
#define ctf_array_nowrite_hex(_type, _item, _src, _length)

#undef ctf_array_network_nowrite
#define ctf_array_network_nowrite(_type, _item, _src, _length)

#undef ctf_array_network_nowrite_hex
#define ctf_array_network_nowrite_hex(_type, _item, _src, _length)

#undef ctf_array_text_nowrite
#define ctf_array_text_nowrite(_type, _item, _src, _length)

#undef ctf_sequence_nowrite
#define ctf_sequence_nowrite(_type, _item, _src, _length_type, _src_length)

#undef ctf_sequence_nowrite_hex
#define ctf_sequence_nowrite_hex(_type, _item, _src, _length_type, _src_length)

#undef ctf_sequence_network_nowrite
#define ctf_sequence_network_nowrite(_type, _item, _src, _length_type, _src_length)

#undef ctf_sequence_network_nowrite_hex
#define ctf_sequence_network_nowrite_hex(_type, _item, _src, _length_type, _src_length)

#undef ctf_sequence_text_nowrite
#define ctf_sequence_text_nowrite(_type, _item, _src, _length_type, _src_length)

#undef ctf_string_nowrite
#define ctf_string_nowrite(_item, _src)

#undef ctf_enum_nowrite
#define ctf_enum_nowrite(_provider, _name, _type, _item, _src)
