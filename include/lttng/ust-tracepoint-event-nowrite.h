/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#undef lttng_ust_field_integer_nowrite
#define lttng_ust_field_integer_nowrite(_type, _item, _src)			\
	lttng_ust__field_integer_ext(_type, _item, _src, LTTNG_UST_BYTE_ORDER, 10, 1)

#undef lttng_ust_field_float_nowrite
#define lttng_ust_field_float_nowrite(_type, _item, _src)			\
	lttng_ust__field_float(_type, _item, _src, 1)

#undef lttng_ust_field_array_nowrite
#define lttng_ust_field_array_nowrite(_type, _item, _src, _length)		\
	lttng_ust__field_array_encoded(_type, _item, _src, LTTNG_UST_BYTE_ORDER, _length, none, 1, 10)

#undef lttng_ust_field_array_nowrite_hex
#define lttng_ust_field_array_nowrite_hex(_type, _item, _src, _length)	\
	lttng_ust__field_array_encoded(_type, _item, _src, LTTNG_UST_BYTE_ORDER, _length, none, 1, 16)

#undef lttng_ust_field_array_network_nowrite
#define lttng_ust_field_array_network_nowrite(_type, _item, _src, _length)	\
	lttng_ust__field_array_encoded(_type, _item, _src, LTTNG_UST_BIG_ENDIAN,	\
			_length, none, 1, 10)

#undef lttng_ust_field_array_network_nowrite_hex
#define lttng_ust_field_array_network_nowrite_hex(_type, _item, _src, _length) \
	lttng_ust__field_array_encoded(_type, _item, _src, LTTNG_UST_BIG_ENDIAN,	\
			_length, none, 1, 16)

#undef lttng_ust_field_array_text_nowrite
#define lttng_ust_field_array_text_nowrite(_type, _item, _src, _length)	\
	lttng_ust__field_array_encoded(_type, _item, _src, LTTNG_UST_BYTE_ORDER, _length, UTF8, 1, 10)

#undef lttng_ust_field_sequence_nowrite
#define lttng_ust_field_sequence_nowrite(_type, _item, _src, _length_type, _src_length) \
	lttng_ust__field_sequence_encoded(_type, _item, _src, LTTNG_UST_BYTE_ORDER,	\
			_length_type, _src_length, none, 1, 10)

#undef lttng_ust_field_sequence_nowrite_hex
#define lttng_ust_field_sequence_nowrite_hex(_type, _item, _src, _length_type, _src_length) \
	lttng_ust__field_sequence_encoded(_type, _item, _src, LTTNG_UST_BYTE_ORDER,	\
			_length_type, _src_length, none, 1, 16)

#undef lttng_ust_field_sequence_network_nowrite
#define lttng_ust_field_sequence_network_nowrite(_type, _item, _src, _length_type, _src_length) \
	lttng_ust__field_sequence_encoded(_type, _item, _src, LTTNG_UST_BIG_ENDIAN,	\
			_length_type, _src_length, none, 1, 10)

#undef lttng_ust_field_sequence_network_nowrite_hex
#define lttng_ust_field_sequence_network_nowrite_hex(_type, _item, _src, _length_type, _src_length) \
	lttng_ust__field_sequence_encoded(_type, _item, _src, LTTNG_UST_BIG_ENDIAN,	\
			_length_type, _src_length, none, 1, 16)

#undef lttng_ust_field_sequence_text_nowrite
#define lttng_ust_field_sequence_text_nowrite(_type, _item, _src, _length_type, _src_length) \
	lttng_ust__field_sequence_encoded(_type, _item, _src, LTTNG_UST_BYTE_ORDER,	\
			_length_type, _src_length, UTF8, 1, 10)

#undef lttng_ust_field_string_nowrite
#define lttng_ust_field_string_nowrite(_item, _src)				\
	lttng_ust__field_string(_item, _src, 1)

#undef lttng_ust_field_unused_nowrite
#define lttng_ust_field_unused_nowrite(_src)				\
	lttng_ust__field_unused(_src)

#undef ctf_enum_nowrite
#define ctf_enum_nowrite(_provider, _name, _type, _item, _src)		\
	_ctf_enum(_provider, _name, _type, _item, _src, 1)
