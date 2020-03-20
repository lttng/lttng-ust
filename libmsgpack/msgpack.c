/*
 * msgpack.c
 *
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; only
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#define _GNU_SOURCE
#define _LGPL_SOURCE
#include <stddef.h>

#define MSGPACK_FIXSTR_ID_MASK		0xA0
#define MSGPACK_FIXMAP_ID_MASK		0x80
#define MSGPACK_FIXARRAY_ID_MASK	0x90

#define MSGPACK_NIL_ID		0xC0
#define MSGPACK_FALSE_ID	0xC2
#define MSGPACK_TRUE_ID		0xC3
#define MSGPACK_MAP16_ID	0xDE
#define MSGPACK_ARRAY16_ID	0xDC

#define MSGPACK_UINT8_ID	0xCC
#define MSGPACK_UINT16_ID	0xCD
#define MSGPACK_UINT32_ID	0xCE
#define MSGPACK_UINT64_ID	0xCF

#define MSGPACK_INT8_ID		0xD0
#define MSGPACK_INT16_ID	0xD1
#define MSGPACK_INT32_ID	0xD2
#define MSGPACK_INT64_ID	0xD3

#define MSGPACK_FLOAT64_ID	0xCB
#define MSGPACK_STR16_ID	0xDA

#define MSGPACK_FIXINT_MAX		((1 << 7) - 1)
#define MSGPACK_FIXINT_MIN		-(1 << 5)
#define MSGPACK_FIXMAP_MAX_COUNT	15
#define MSGPACK_FIXARRAY_MAX_COUNT	15
#define MSGPACK_FIXSTR_MAX_LENGTH	31

#ifdef __KERNEL__
#include <linux/bug.h>
#include <linux/string.h>
#include <linux/types.h>

#include <lttng/msgpack.h>

#define INT8_MIN		(-128)
#define INT16_MIN		(-32767-1)
#define INT32_MIN		(-2147483647-1)
#define INT8_MAX		(127)
#define INT16_MAX		(32767)
#define INT32_MAX		(2147483647)
#define UINT8_MAX		(255)
#define UINT16_MAX		(65535)
#define UINT32_MAX		(4294967295U)

#define byteswap_host_to_be16(_tmp) cpu_to_be16(_tmp)
#define byteswap_host_to_be32(_tmp) cpu_to_be32(_tmp)
#define byteswap_host_to_be64(_tmp) cpu_to_be64(_tmp)

#define lttng_msgpack_assert(cond) WARN_ON(!(cond))

#else /* __KERNEL__ */

#include <endian.h>
#include <stdio.h>
#include <string.h>

#include "msgpack.h"

#define byteswap_host_to_be16(_tmp) htobe16(_tmp)
#define byteswap_host_to_be32(_tmp) htobe32(_tmp)
#define byteswap_host_to_be64(_tmp) htobe64(_tmp)

#define lttng_msgpack_assert(cond) ({ \
	if (!(cond)) \
		fprintf(stderr, "Assertion failed. %s:%d\n", __FILE__, __LINE__); \
	})
#endif /* __KERNEL__ */

static inline int lttng_msgpack_append_buffer(
		struct lttng_msgpack_writer *writer,
		const uint8_t *buf,
		size_t length)
{
	int ret = 0;

	lttng_msgpack_assert(buf);

	/* Ensure we are not trying to write after the end of the buffer. */
	if (writer->write_pos + length > writer->end_write_pos) {
		ret = -1;
		goto end;
	}

	memcpy(writer->write_pos, buf, length);
	writer->write_pos += length;
end:
	return ret;
}

static inline int lttng_msgpack_append_u8(
		struct lttng_msgpack_writer *writer, uint8_t value)
{
	return lttng_msgpack_append_buffer(writer, &value, sizeof(value));
}

static inline int lttng_msgpack_append_u16(
		struct lttng_msgpack_writer *writer, uint16_t value)
{
	value = byteswap_host_to_be16(value);

	return lttng_msgpack_append_buffer(writer, (uint8_t *) &value, sizeof(value));
}

static inline int lttng_msgpack_append_u32(
		struct lttng_msgpack_writer *writer, uint32_t value)
{
	value = byteswap_host_to_be32(value);

	return lttng_msgpack_append_buffer(writer, (uint8_t *) &value, sizeof(value));
}

static inline int lttng_msgpack_append_u64(
		struct lttng_msgpack_writer *writer, uint64_t value)
{
	value = byteswap_host_to_be64(value);

	return lttng_msgpack_append_buffer(writer, (uint8_t *) &value, sizeof(value));
}

static inline int lttng_msgpack_append_f64(
		struct lttng_msgpack_writer *writer, double value)
{

	union {
		double d;
		uint64_t u;
	} u;

	u.d = value;

	return lttng_msgpack_append_u64(writer, u.u);
}

static inline int lttng_msgpack_append_i8(
		struct lttng_msgpack_writer *writer, int8_t value)
{
	return lttng_msgpack_append_u8(writer, (uint8_t) value);
}

static inline int lttng_msgpack_append_i16(
		struct lttng_msgpack_writer *writer, int16_t value)
{
	return lttng_msgpack_append_u16(writer, (uint16_t) value);
}

static inline int lttng_msgpack_append_i32(
		struct lttng_msgpack_writer *writer, int32_t value)
{
	return lttng_msgpack_append_u32(writer, (uint32_t) value);
}

static inline int lttng_msgpack_append_i64(
		struct lttng_msgpack_writer *writer, int64_t value)
{
	return lttng_msgpack_append_u64(writer, (uint64_t) value);
}

static inline int lttng_msgpack_encode_f64(
		struct lttng_msgpack_writer *writer, double value)
{
	int ret;

	ret = lttng_msgpack_append_u8(writer, MSGPACK_FLOAT64_ID);
	if (ret)
		goto end;

	ret = lttng_msgpack_append_f64(writer, value);
	if (ret)
		goto end;

end:
	return ret;
}

static inline int lttng_msgpack_encode_fixmap(
		struct lttng_msgpack_writer *writer, uint8_t count)
{
	int ret = 0;

	lttng_msgpack_assert(count <= MSGPACK_FIXMAP_MAX_COUNT);

	ret = lttng_msgpack_append_u8(writer, MSGPACK_FIXMAP_ID_MASK | count);
	if (ret)
		goto end;

end:
	return ret;
}

static inline int lttng_msgpack_encode_map16(
		struct lttng_msgpack_writer *writer, uint16_t count)
{
	int ret;

	lttng_msgpack_assert(count > MSGPACK_FIXMAP_MAX_COUNT);

	ret = lttng_msgpack_append_u8(writer, MSGPACK_MAP16_ID);
	if (ret)
		goto end;

	ret = lttng_msgpack_append_u16(writer, count);
	if (ret)
		goto end;

end:
	return ret;
}

static inline int lttng_msgpack_encode_fixarray(
		struct lttng_msgpack_writer *writer, uint8_t count)
{
	int ret = 0;

	lttng_msgpack_assert(count <= MSGPACK_FIXARRAY_MAX_COUNT);

	ret = lttng_msgpack_append_u8(writer, MSGPACK_FIXARRAY_ID_MASK | count);
	if (ret)
		goto end;

end:
	return ret;
}

static inline int lttng_msgpack_encode_array16(
		struct lttng_msgpack_writer *writer, uint16_t count)
{
	int ret;

	lttng_msgpack_assert(count > MSGPACK_FIXARRAY_MAX_COUNT);

	ret = lttng_msgpack_append_u8(writer, MSGPACK_ARRAY16_ID);
	if (ret)
		goto end;

	ret = lttng_msgpack_append_u16(writer, count);
	if (ret)
		goto end;

end:
	return ret;
}

static inline int lttng_msgpack_encode_fixstr(
		struct lttng_msgpack_writer *writer,
		const char *str,
		uint8_t len)
{
	int ret;

	lttng_msgpack_assert(len <= MSGPACK_FIXSTR_MAX_LENGTH);

	ret = lttng_msgpack_append_u8(writer, MSGPACK_FIXSTR_ID_MASK | len);
	if (ret)
		goto end;

	ret = lttng_msgpack_append_buffer(writer, (uint8_t *) str, len);
	if (ret)
		goto end;

end:
	return ret;
}

static inline int lttng_msgpack_encode_str16(
		struct lttng_msgpack_writer *writer,
		const char *str,
		uint16_t len)
{
	int ret;

	lttng_msgpack_assert(len > MSGPACK_FIXSTR_MAX_LENGTH);

	ret = lttng_msgpack_append_u8(writer, MSGPACK_STR16_ID);
	if (ret)
		goto end;

	ret = lttng_msgpack_append_u16(writer, len);
	if (ret)
		goto end;

	ret = lttng_msgpack_append_buffer(writer, (uint8_t *) str, len);
	if (ret)
		goto end;

end:
	return ret;
}

int lttng_msgpack_begin_map(struct lttng_msgpack_writer *writer, size_t count)
{
	int ret;

	if (count < 0 || count >= (1 << 16)) {
		ret = -1;
		goto end;
	}

	if (count <= MSGPACK_FIXMAP_MAX_COUNT)
		ret = lttng_msgpack_encode_fixmap(writer, count);
	else
		ret = lttng_msgpack_encode_map16(writer, count);

	writer->map_nesting++;
end:
	return ret;
}

int lttng_msgpack_end_map(struct lttng_msgpack_writer *writer)
{
	lttng_msgpack_assert(writer->map_nesting > 0);
	writer->map_nesting--;
	return 0;
}

int lttng_msgpack_begin_array(
		struct lttng_msgpack_writer *writer, size_t count)
{
	int ret;

	if (count < 0 || count >= (1 << 16)) {
		ret = -1;
		goto end;
	}

	if (count <= MSGPACK_FIXARRAY_MAX_COUNT)
		ret = lttng_msgpack_encode_fixarray(writer, count);
	else
		ret = lttng_msgpack_encode_array16(writer, count);

	writer->array_nesting++;
end:
	return ret;
}

int lttng_msgpack_end_array(struct lttng_msgpack_writer *writer)
{
	lttng_msgpack_assert(writer->array_nesting > 0);
	writer->array_nesting--;
	return 0;
}

int lttng_msgpack_write_str(struct lttng_msgpack_writer *writer,
		const char *str)
{
	int ret;
	size_t length = strlen(str);
	if (length < 0 || length >= (1 << 16)) {
		ret = -1;
		goto end;
	}

	if (length <= MSGPACK_FIXSTR_MAX_LENGTH)
		ret = lttng_msgpack_encode_fixstr(writer, str, length);
	else
		ret = lttng_msgpack_encode_str16(writer, str, length);

end:
	return ret;
}

int lttng_msgpack_write_nil(struct lttng_msgpack_writer *writer)
{
	return lttng_msgpack_append_u8(writer, MSGPACK_NIL_ID);
}

int lttng_msgpack_write_true(struct lttng_msgpack_writer *writer)
{
	return lttng_msgpack_append_u8(writer, MSGPACK_TRUE_ID);
}

int lttng_msgpack_write_false(struct lttng_msgpack_writer *writer)
{
	return lttng_msgpack_append_u8(writer, MSGPACK_FALSE_ID);
}

int lttng_msgpack_write_unsigned_integer(
		struct lttng_msgpack_writer *writer, uint64_t value)
{
	int ret = 0;

	if (value <= MSGPACK_FIXINT_MAX) {
		ret = lttng_msgpack_append_u8(writer, (uint8_t) value);
		if (ret)
			goto end;
	} else if (value <= UINT8_MAX) {
		ret = lttng_msgpack_append_u8(writer, MSGPACK_UINT8_ID);
		if (ret)
			goto end;

		ret = lttng_msgpack_append_u8(writer, (uint8_t) value);
		if (ret)
			goto end;
	} else if (value <= UINT16_MAX) {
		ret = lttng_msgpack_append_u8(writer, MSGPACK_UINT16_ID);
		if (ret)
			goto end;

		ret = lttng_msgpack_append_u16(writer, (uint16_t) value);
		if (ret)
			goto end;
	} else if (value <= UINT32_MAX) {
		ret = lttng_msgpack_append_u8(writer, MSGPACK_UINT32_ID);
		if (ret)
			goto end;

		ret = lttng_msgpack_append_u32(writer, (uint32_t) value);
		if (ret)
			goto end;
	} else {
		ret = lttng_msgpack_append_u8(writer, MSGPACK_UINT64_ID);
		if (ret)
			goto end;

		ret = lttng_msgpack_append_u64(writer, value);
		if (ret)
			goto end;
	}

end:
	return ret;
}

int lttng_msgpack_write_signed_integer(struct lttng_msgpack_writer *writer, int64_t value)
{
	int ret;

	if (value >= MSGPACK_FIXINT_MIN && value <= MSGPACK_FIXINT_MAX){
		ret = lttng_msgpack_append_i8(writer, (int8_t) value);
		if (ret)
			goto end;
	} else if (value >= INT8_MIN && value <= INT8_MAX) {
		ret = lttng_msgpack_append_u8(writer, MSGPACK_INT8_ID);
		if (ret)
			goto end;

		ret = lttng_msgpack_append_i8(writer, (int8_t) value);
		if (ret)
			goto end;
	} else if (value >= INT16_MIN && value <= INT16_MAX) {
		ret = lttng_msgpack_append_u8(writer, MSGPACK_INT16_ID);
		if (ret)
			goto end;

		ret = lttng_msgpack_append_i16(writer, (int16_t) value);
		if (ret)
			goto end;
	} else if (value >= INT32_MIN && value <= INT32_MAX) {
		ret = lttng_msgpack_append_u8(writer, MSGPACK_INT32_ID);
		if (ret)
			goto end;

		ret = lttng_msgpack_append_i32(writer, (int32_t) value);
		if (ret)
			goto end;
	} else {
		ret = lttng_msgpack_append_u8(writer, MSGPACK_INT64_ID);
		if (ret)
			goto end;

		ret = lttng_msgpack_append_i64(writer, value);
		if (ret)
			goto end;
	}

end:
	return ret;
}

int lttng_msgpack_write_double(struct lttng_msgpack_writer *writer, double value)
{
	return lttng_msgpack_encode_f64(writer, value);
}

void lttng_msgpack_writer_init(struct lttng_msgpack_writer *writer,
		uint8_t *buffer, size_t size)
{
	lttng_msgpack_assert(buffer);
	lttng_msgpack_assert(size >= 0);

	writer->buffer = buffer;
	writer->write_pos = buffer;
	writer->end_write_pos = buffer + size;

	writer->array_nesting = 0;
	writer->map_nesting = 0;
}

void lttng_msgpack_writer_fini(struct lttng_msgpack_writer *writer)
{
	memset(writer, 0, sizeof(*writer));
}
