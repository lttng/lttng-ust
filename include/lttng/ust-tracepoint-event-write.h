/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

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

#undef ctf_array
#define ctf_array(_type, _item, _src, _length)			\
	_ctf_array_encoded(_type, _item, _src, LTTNG_UST_BYTE_ORDER,	\
			_length, none, 0, 10)

#undef ctf_array_hex
#define ctf_array_hex(_type, _item, _src, _length)		\
	_ctf_array_encoded(_type, _item, _src, LTTNG_UST_BYTE_ORDER,	\
			_length, none, 0, 16)

#undef ctf_array_network
#define ctf_array_network(_type, _item, _src, _length)	\
	_ctf_array_encoded(_type, _item, _src, LTTNG_UST_BIG_ENDIAN,	\
			_length, none, 0, 10)

#undef ctf_array_network_hex
#define ctf_array_network_hex(_type, _item, _src, _length)	\
	_ctf_array_encoded(_type, _item, _src, LTTNG_UST_BIG_ENDIAN,	\
			_length, none, 0, 16)

#undef ctf_array_text
#define ctf_array_text(_type, _item, _src, _length)		\
	_ctf_array_encoded(_type, _item, _src, LTTNG_UST_BYTE_ORDER,	\
			_length, UTF8, 0, 10)

#undef ctf_sequence
#define ctf_sequence(_type, _item, _src, _length_type, _src_length) \
	_ctf_sequence_encoded(_type, _item, _src, LTTNG_UST_BYTE_ORDER,	\
			_length_type, _src_length, none, 0, 10)

#undef ctf_sequence_hex
#define ctf_sequence_hex(_type, _item, _src, _length_type, _src_length) \
	_ctf_sequence_encoded(_type, _item, _src, LTTNG_UST_BYTE_ORDER,	\
			_length_type, _src_length, none, 0, 16)

#undef ctf_sequence_network
#define ctf_sequence_network(_type, _item, _src, _length_type, _src_length) \
	_ctf_sequence_encoded(_type, _item, _src, LTTNG_UST_BIG_ENDIAN,	\
			_length_type, _src_length, none, 0, 10)

#undef ctf_sequence_network_hex
#define ctf_sequence_network_hex(_type, _item, _src, _length_type, _src_length) \
	_ctf_sequence_encoded(_type, _item, _src, LTTNG_UST_BIG_ENDIAN,	\
			_length_type, _src_length, none, 0, 16)

#undef ctf_sequence_text
#define ctf_sequence_text(_type, _item, _src, _length_type, _src_length) \
	_ctf_sequence_encoded(_type, _item, _src, LTTNG_UST_BYTE_ORDER,	\
			_length_type, _src_length, UTF8, 0, 10)

#undef ctf_string
#define ctf_string(_item, _src)					\
	_ctf_string(_item, _src, 0)

#undef ctf_unused
#define ctf_unused(_src)					\
	_ctf_unused(_src)

#undef ctf_enum
#define ctf_enum(_provider, _name, _type, _item, _src)			\
	_ctf_enum(_provider, _name, _type, _item, _src, 0)
