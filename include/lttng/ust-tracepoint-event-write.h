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

#undef ctf_integer
#define ctf_integer(_type, _item, _src)				\
	_ctf_integer_ext(_type, _item, _src, BYTE_ORDER, 10, 1)

#undef ctf_integer_hex
#define ctf_integer_hex(_type, _item, _src)			\
	_ctf_integer_ext(_type, _item, _src, BYTE_ORDER, 16, 1)

#undef ctf_integer_network
#define ctf_integer_network(_type, _item, _src)			\
	_ctf_integer_ext(_type, _item, _src, BIG_ENDIAN, 10, 1)

#undef ctf_integer_network_hex
#define ctf_integer_network_hex(_type, _item, _src)		\
	_ctf_integer_ext(_type, _item, _src, BIG_ENDIAN, 16, 1)

#undef ctf_float
#define ctf_float(_type, _item, _src)				\
	_ctf_float(_type, _item, _src, 1)

#undef ctf_array
#define ctf_array(_type, _item, _src, _length)			\
	_ctf_array_encoded(_type, _item, _src, _length, none, 1)

#undef ctf_array_text
#define ctf_array_text(_type, _item, _src, _length)		\
	_ctf_array_encoded(_type, _item, _src, _length, UTF8, 1)

#undef ctf_sequence
#define ctf_sequence(_type, _item, _src, _length_type, _src_length) \
	_ctf_sequence_encoded(_type, _item, _src,		\
			_length_type, _src_length, none, 1)

#undef ctf_sequence_text
#define ctf_sequence_text(_type, _item, _src, _length_type, _src_length) \
	_ctf_sequence_encoded(_type, _item, _src,		\
			_length_type, _src_length, UTF8, 1)

#undef ctf_string
#define ctf_string(_item, _src)					\
	_ctf_string(_item, _src, 1)
