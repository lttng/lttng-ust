// SPDX-FileCopyrightText: 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
//
// SPDX-License-Identifier: MIT

#undef lttng_ust_field_integer
#define lttng_ust_field_integer(_type, _item, _src)				\
	lttng_ust__field_integer_ext(_type, _item, _src, LTTNG_UST_BYTE_ORDER, 10, 0)

#undef lttng_ust_field_integer_hex
#define lttng_ust_field_integer_hex(_type, _item, _src)			\
	lttng_ust__field_integer_ext(_type, _item, _src, LTTNG_UST_BYTE_ORDER, 16, 0)

#undef lttng_ust_field_integer_network
#define lttng_ust_field_integer_network(_type, _item, _src)			\
	lttng_ust__field_integer_ext(_type, _item, _src, LTTNG_UST_BIG_ENDIAN, 10, 0)

#undef lttng_ust_field_integer_network_hex
#define lttng_ust_field_integer_network_hex(_type, _item, _src)		\
	lttng_ust__field_integer_ext(_type, _item, _src, LTTNG_UST_BIG_ENDIAN, 16, 0)

#undef lttng_ust_field_float
#define lttng_ust_field_float(_type, _item, _src)				\
	lttng_ust__field_float(_type, _item, _src, 0)

#undef lttng_ust_field_array
#define lttng_ust_field_array(_type, _item, _src, _length)			\
	lttng_ust__field_array_encoded(_type, _item, _src, LTTNG_UST_BYTE_ORDER,	\
			_length, none, 0, 10)

#undef lttng_ust_field_array_hex
#define lttng_ust_field_array_hex(_type, _item, _src, _length)		\
	lttng_ust__field_array_encoded(_type, _item, _src, LTTNG_UST_BYTE_ORDER,	\
			_length, none, 0, 16)

#undef lttng_ust_field_array_network
#define lttng_ust_field_array_network(_type, _item, _src, _length)	\
	lttng_ust__field_array_encoded(_type, _item, _src, LTTNG_UST_BIG_ENDIAN,	\
			_length, none, 0, 10)

#undef lttng_ust_field_array_network_hex
#define lttng_ust_field_array_network_hex(_type, _item, _src, _length)	\
	lttng_ust__field_array_encoded(_type, _item, _src, LTTNG_UST_BIG_ENDIAN,	\
			_length, none, 0, 16)

#undef lttng_ust_field_array_text
#define lttng_ust_field_array_text(_type, _item, _src, _length)		\
	lttng_ust__field_array_encoded(_type, _item, _src, LTTNG_UST_BYTE_ORDER,	\
			_length, UTF8, 0, 10)

#undef lttng_ust_field_sequence
#define lttng_ust_field_sequence(_type, _item, _src, _length_type, _src_length) \
	lttng_ust__field_sequence_encoded(_type, _item, _src, LTTNG_UST_BYTE_ORDER,	\
			_length_type, _src_length, none, 0, 10)

#undef lttng_ust_field_sequence_hex
#define lttng_ust_field_sequence_hex(_type, _item, _src, _length_type, _src_length) \
	lttng_ust__field_sequence_encoded(_type, _item, _src, LTTNG_UST_BYTE_ORDER,	\
			_length_type, _src_length, none, 0, 16)

#undef lttng_ust_field_sequence_network
#define lttng_ust_field_sequence_network(_type, _item, _src, _length_type, _src_length) \
	lttng_ust__field_sequence_encoded(_type, _item, _src, LTTNG_UST_BIG_ENDIAN,	\
			_length_type, _src_length, none, 0, 10)

#undef lttng_ust_field_sequence_network_hex
#define lttng_ust_field_sequence_network_hex(_type, _item, _src, _length_type, _src_length) \
	lttng_ust__field_sequence_encoded(_type, _item, _src, LTTNG_UST_BIG_ENDIAN,	\
			_length_type, _src_length, none, 0, 16)

#undef lttng_ust_field_sequence_text
#define lttng_ust_field_sequence_text(_type, _item, _src, _length_type, _src_length) \
	lttng_ust__field_sequence_encoded(_type, _item, _src, LTTNG_UST_BYTE_ORDER,	\
			_length_type, _src_length, UTF8, 0, 10)

#undef lttng_ust_field_string
#define lttng_ust_field_string(_item, _src)					\
	lttng_ust__field_string(_item, _src, 0)

#undef lttng_ust_field_unused
#define lttng_ust_field_unused(_src)					\
	lttng_ust__field_unused(_src)

#undef lttng_ust_field_enum
#define lttng_ust_field_enum(_provider, _name, _type, _item, _src)			\
	lttng_ust__field_enum(_provider, _name, _type, _item, _src, 0)
