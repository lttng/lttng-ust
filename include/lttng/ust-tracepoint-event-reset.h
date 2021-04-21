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

#undef LTTNG_UST_TRACEPOINT_LOGLEVEL
#define LTTNG_UST_TRACEPOINT_LOGLEVEL(provider, name, loglevel)

#undef LTTNG_UST_TRACEPOINT_MODEL_EMF_URI
#define LTTNG_UST_TRACEPOINT_MODEL_EMF_URI(provider, name, uri)

#undef lttng_ust__field_integer_ext
#define lttng_ust__field_integer_ext(_type, _item, _src, _byte_order, _base, \
			_nowrite)

#undef lttng_ust__field_float
#define lttng_ust__field_float(_type, _item, _src, _nowrite)

#undef lttng_ust__field_array_encoded
#define lttng_ust__field_array_encoded(_type, _item, _src, _byte_order, _length, _encoding, \
			_nowrite, _elem_type_base)

#undef lttng_ust__field_sequence_encoded
#define lttng_ust__field_sequence_encoded(_type, _item, _src, _byte_order, _length_type, \
			_src_length, _encoding, _nowrite, _elem_type_base)

#undef lttng_ust__field_string
#define lttng_ust__field_string(_item, _src, _nowrite)

#undef _ctf_unused
#define _ctf_unused(_src)

#undef _ctf_enum
#define _ctf_enum(_provider, _name, _type, _item, _src, _nowrite)

/* "write" */
#undef lttng_ust_field_integer
#define lttng_ust_field_integer(_type, _item, _src)

#undef lttng_ust_field_integer_hex
#define lttng_ust_field_integer_hex(_type, _item, _src)

#undef lttng_ust_field_integer_network
#define lttng_ust_field_integer_network(_type, _item, _src)

#undef lttng_ust_field_integer_network_hex
#define lttng_ust_field_integer_network_hex(_type, _item, _src)

#undef lttng_ust_field_float
#define lttng_ust_field_float(_type, _item, _src)

#undef lttng_ust_field_array
#define lttng_ust_field_array(_type, _item, _src, _length)

#undef lttng_ust_field_array_hex
#define lttng_ust_field_array_hex(_type, _item, _src, _length)

#undef lttng_ust_field_array_network
#define lttng_ust_field_array_network(_type, _item, _src, _length)

#undef lttng_ust_field_array_network_hex
#define lttng_ust_field_array_network_hex(_type, _item, _src, _length)

#undef lttng_ust_field_array_text
#define lttng_ust_field_array_text(_type, _item, _src, _length)

#undef lttng_ust_field_sequence
#define lttng_ust_field_sequence(_type, _item, _src, _length_type, _src_length)

#undef lttng_ust_field_sequence_hex
#define lttng_ust_field_sequence_hex(_type, _item, _src, _length_type, _src_length)

#undef lttng_ust_field_sequence_network
#define lttng_ust_field_sequence_network(_type, _item, _src, _length_type, _src_length)

#undef lttng_ust_field_sequence_network_hex
#define lttng_ust_field_sequence_network_hex(_type, _item, _src, _length_type, _src_length)

#undef lttng_ust_field_sequence_text
#define lttng_ust_field_sequence_text(_type, _item, _src, _length_type, _src_length)

#undef lttng_ust_field_string
#define lttng_ust_field_string(_item, _src)

#undef ctf_unused
#define ctf_unused(_src)

#undef ctf_enum
#define ctf_enum(_provider, _name, _type, _item, _src)

/* "nowrite" */
#undef lttng_ust_field_integer_nowrite
#define lttng_ust_field_integer_nowrite(_type, _item, _src)

#undef lttng_ust_field_float_nowrite
#define lttng_ust_field_float_nowrite(_type, _item, _src)

#undef lttng_ust_field_array_nowrite
#define lttng_ust_field_array_nowrite(_type, _item, _src, _length)

#undef lttng_ust_field_array_nowrite_hex
#define lttng_ust_field_array_nowrite_hex(_type, _item, _src, _length)

#undef lttng_ust_field_array_network_nowrite
#define lttng_ust_field_array_network_nowrite(_type, _item, _src, _length)

#undef lttng_ust_field_array_network_nowrite_hex
#define lttng_ust_field_array_network_nowrite_hex(_type, _item, _src, _length)

#undef lttng_ust_field_array_text_nowrite
#define lttng_ust_field_array_text_nowrite(_type, _item, _src, _length)

#undef lttng_ust_field_sequence_nowrite
#define lttng_ust_field_sequence_nowrite(_type, _item, _src, _length_type, _src_length)

#undef lttng_ust_field_sequence_nowrite_hex
#define lttng_ust_field_sequence_nowrite_hex(_type, _item, _src, _length_type, _src_length)

#undef lttng_ust_field_sequence_network_nowrite
#define lttng_ust_field_sequence_network_nowrite(_type, _item, _src, _length_type, _src_length)

#undef lttng_ust_field_sequence_network_nowrite_hex
#define lttng_ust_field_sequence_network_nowrite_hex(_type, _item, _src, _length_type, _src_length)

#undef lttng_ust_field_sequence_text_nowrite
#define lttng_ust_field_sequence_text_nowrite(_type, _item, _src, _length_type, _src_length)

#undef lttng_ust_field_string_nowrite
#define lttng_ust_field_string_nowrite(_item, _src)

#undef ctf_unused_nowrite
#define ctf_unused_nowrite(_src)

#undef ctf_enum_nowrite
#define ctf_enum_nowrite(_provider, _name, _type, _item, _src)
