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

#undef ctf_integer
#define ctf_integer(_type, _item, _src)				\
	_ctf_integer_ext(_type, _item, _src, BYTE_ORDER, 10, 0)

#undef ctf_integer_hex
#define ctf_integer_hex(_type, _item, _src)			\
	_ctf_integer_ext(_type, _item, _src, BYTE_ORDER, 16, 0)

#undef ctf_integer_network
#define ctf_integer_network(_type, _item, _src)			\
	_ctf_integer_ext(_type, _item, _src, BIG_ENDIAN, 10, 0)

#undef ctf_integer_network_hex
#define ctf_integer_network_hex(_type, _item, _src)		\
	_ctf_integer_ext(_type, _item, _src, BIG_ENDIAN, 16, 0)

#undef ctf_float
#define ctf_float(_type, _item, _src)				\
	_ctf_float(_type, _item, _src, 0)

#undef ctf_array
#define ctf_array(_type, _item, _src, _length)			\
	_ctf_array_encoded(_type, _item, _src, BYTE_ORDER,	\
			_length, none, 0, 10)

#undef ctf_array_hex
#define ctf_array_hex(_type, _item, _src, _length)		\
	_ctf_array_encoded(_type, _item, _src, BYTE_ORDER,	\
			_length, none, 0, 16)

#undef ctf_array_network
#define ctf_array_network(_type, _item, _src, _length)	\
	_ctf_array_encoded(_type, _item, _src, BIG_ENDIAN,	\
			_length, none, 0, 10)

#undef ctf_array_network_hex
#define ctf_array_network_hex(_type, _item, _src, _length)	\
	_ctf_array_encoded(_type, _item, _src, BIG_ENDIAN,	\
			_length, none, 0, 16)

#undef ctf_array_text
#define ctf_array_text(_type, _item, _src, _length)		\
	_ctf_array_encoded(_type, _item, _src, BYTE_ORDER,	\
			_length, UTF8, 0, 10)

#undef ctf_sequence
#define ctf_sequence(_type, _item, _src, _length_type, _src_length) \
	_ctf_sequence_encoded(_type, _item, _src, BYTE_ORDER,	\
			_length_type, _src_length, none, 0, 10)

#undef ctf_sequence_hex
#define ctf_sequence_hex(_type, _item, _src, _length_type, _src_length) \
	_ctf_sequence_encoded(_type, _item, _src, BYTE_ORDER,	\
			_length_type, _src_length, none, 0, 16)

#undef ctf_sequence_network
#define ctf_sequence_network(_type, _item, _src, _length_type, _src_length) \
	_ctf_sequence_encoded(_type, _item, _src, BIG_ENDIAN,	\
			_length_type, _src_length, none, 0, 10)

#undef ctf_sequence_network_hex
#define ctf_sequence_network_hex(_type, _item, _src, _length_type, _src_length) \
	_ctf_sequence_encoded(_type, _item, _src, BIG_ENDIAN,	\
			_length_type, _src_length, none, 0, 16)

#undef ctf_sequence_text
#define ctf_sequence_text(_type, _item, _src, _length_type, _src_length) \
	_ctf_sequence_encoded(_type, _item, _src, BYTE_ORDER,	\
			_length_type, _src_length, UTF8, 0, 10)

#undef ctf_string
#define ctf_string(_item, _src)					\
	_ctf_string(_item, _src, 0)

#undef ctf_enum
#define ctf_enum(_provider, _name, _type, _item, _src)			\
	_ctf_enum(_provider, _name, _type, _item, _src, 0)
