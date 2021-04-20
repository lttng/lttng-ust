/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

/* Define to "nothing" all macros used for LTTNG_UST_TRACEPOINT_EVENT */

#undef LTTNG_UST__TRACEPOINT_EVENT_CLASS
#define LTTNG_UST__TRACEPOINT_EVENT_CLASS(_provider, _name, _args, _fields)

#undef LTTNG_UST__TRACEPOINT_EVENT_INSTANCE
#define LTTNG_UST__TRACEPOINT_EVENT_INSTANCE(_provider, _template, _name, _args)

#undef LTTNG_UST_TRACEPOINT_ENUM
#define LTTNG_UST_TRACEPOINT_ENUM(_provider, _name, _values)

#undef LTTNG_UST_TP_ARGS
#define LTTNG_UST_TP_ARGS(...)

#undef LTTNG_UST_TP_FIELDS
#define LTTNG_UST_TP_FIELDS(...)

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

#undef _ctf_unused
#define _ctf_unused(_src)

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

#undef ctf_unused
#define ctf_unused(_src)

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

#undef ctf_unused_nowrite
#define ctf_unused_nowrite(_src)

#undef ctf_enum_nowrite
#define ctf_enum_nowrite(_provider, _name, _type, _item, _src)
