#ifndef _LTTNG_UST_MSGPACK_H
#define _LTTNG_UST_MSGPACK_H

/*
 * msgpack.h
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

#include <stddef.h>
#ifdef __KERNEL__
#include <linux/types.h>
#else /* __KERNEL__ */
#include <stdint.h>
#endif /* __KERNEL__ */

struct lttng_msgpack_writer {
	uint8_t *buffer;
	uint8_t *write_pos;
	const uint8_t *end_write_pos;
	uint8_t array_nesting;
	uint8_t map_nesting;
};

void lttng_msgpack_writer_init(
		struct lttng_msgpack_writer *writer,
		uint8_t *buffer, size_t size);

void lttng_msgpack_writer_fini(struct lttng_msgpack_writer *writer);

int lttng_msgpack_write_nil(struct lttng_msgpack_writer *writer);
int lttng_msgpack_write_true(struct lttng_msgpack_writer *writer);
int lttng_msgpack_write_false(struct lttng_msgpack_writer *writer);
int lttng_msgpack_write_unsigned_integer(
		struct lttng_msgpack_writer *writer, uint64_t value);
int lttng_msgpack_write_signed_integer(
		struct lttng_msgpack_writer *writer, int64_t value);
int lttng_msgpack_write_double(struct lttng_msgpack_writer *writer, double value);
int lttng_msgpack_write_str(struct lttng_msgpack_writer *writer,
		const char *value);
int lttng_msgpack_begin_map(struct lttng_msgpack_writer *writer, size_t count);
int lttng_msgpack_end_map(struct lttng_msgpack_writer *writer);
int lttng_msgpack_begin_array(
		struct lttng_msgpack_writer *writer, size_t count);
int lttng_msgpack_end_array(struct lttng_msgpack_writer *writer);

#endif /* _LTTNG_UST_MSGPACK_H */
