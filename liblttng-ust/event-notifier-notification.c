/*
 * event-notifier-notification.c
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

#define _LGPL_SOURCE

#include <assert.h>
#include <byteswap.h>
#include <errno.h>
#include <lttng/ust-events.h>
#include <usterr-signal-safe.h>

#include "../libmsgpack/msgpack.h"
#include "lttng-bytecode.h"
#include "share.h"

/*
 * We want this write to be atomic AND non-blocking, meaning that we
 * want to write either everything OR nothing.
 * According to `pipe(7)`, writes that are less than `PIPE_BUF` bytes must be
 * atomic, so we bound the capture buffer size to the `PIPE_BUF` minus the size
 * of the notification struct we are sending alongside the capture buffer.
 */
#define CAPTURE_BUFFER_SIZE \
	(PIPE_BUF - sizeof(struct lttng_ust_event_notifier_notification) - 1)

struct lttng_event_notifier_notification {
	int notification_fd;
	uint64_t event_notifier_token;
	uint8_t capture_buf[CAPTURE_BUFFER_SIZE];
	struct lttng_msgpack_writer writer;
	bool has_captures;
};

static
void capture_enum(struct lttng_msgpack_writer *writer,
		struct lttng_interpreter_output *output)
{
	lttng_msgpack_begin_map(writer, 2);
	lttng_msgpack_write_str(writer, "type");
	lttng_msgpack_write_str(writer, "enum");

	lttng_msgpack_write_str(writer, "value");

	switch (output->type) {
	case LTTNG_INTERPRETER_TYPE_SIGNED_ENUM:
		lttng_msgpack_write_signed_integer(writer, output->u.s);
		break;
	case LTTNG_INTERPRETER_TYPE_UNSIGNED_ENUM:
		lttng_msgpack_write_signed_integer(writer, output->u.u);
		break;
	default:
		abort();
	}

	lttng_msgpack_end_map(writer);
}

static
int64_t capture_sequence_element_signed(uint8_t *ptr,
		const struct lttng_integer_type *type)
{
	int64_t value;
	unsigned int size = type->size;
	bool byte_order_reversed = type->reverse_byte_order;

	switch (size) {
	case 8:
		value = *ptr;
		break;
	case 16:
	{
		int16_t tmp;
		tmp = *(int16_t *) ptr;
		if (byte_order_reversed)
			tmp = bswap_16(tmp);

		value = tmp;
		break;
	}
	case 32:
	{
		int32_t tmp;
		tmp = *(int32_t *) ptr;
		if (byte_order_reversed)
			tmp = bswap_32(tmp);

		value = tmp;
		break;
	}
	case 64:
	{
		int64_t tmp;
		tmp = *(int64_t *) ptr;
		if (byte_order_reversed)
			tmp = bswap_64(tmp);

		value = tmp;
		break;
	}
	default:
		abort();
	}

	return value;
}

static
uint64_t capture_sequence_element_unsigned(uint8_t *ptr,
		const struct lttng_integer_type *type)
{
	uint64_t value;
	unsigned int size = type->size;
	bool byte_order_reversed = type->reverse_byte_order;

	switch (size) {
	case 8:
		value = *ptr;
		break;
	case 16:
	{
		uint16_t tmp;
		tmp = *(uint16_t *) ptr;
		if (byte_order_reversed)
			tmp = bswap_16(tmp);

		value = tmp;
		break;
	}
	case 32:
	{
		uint32_t tmp;
		tmp = *(uint32_t *) ptr;
		if (byte_order_reversed)
			tmp = bswap_32(tmp);

		value = tmp;
		break;
	}
	case 64:
	{
		uint64_t tmp;
		tmp = *(uint64_t *) ptr;
		if (byte_order_reversed)
			tmp = bswap_64(tmp);

		value = tmp;
		break;
	}
	default:
		abort();
	}

	return value;
}

static
void capture_sequence(struct lttng_msgpack_writer *writer,
		struct lttng_interpreter_output *output)
{
	const struct lttng_integer_type *integer_type;
	const struct lttng_type *nested_type;
	uint8_t *ptr;
	bool signedness;
	int i;

	lttng_msgpack_begin_array(writer, output->u.sequence.nr_elem);

	ptr = (uint8_t *) output->u.sequence.ptr;
	nested_type = output->u.sequence.nested_type;
	switch (nested_type->atype) {
	case atype_integer:
		integer_type = &nested_type->u.integer;
		break;
	case atype_enum:
		/* Treat enumeration as an integer. */
		integer_type = &nested_type->u.enum_nestable.container_type->u.integer;
		break;
	default:
		/* Capture of array of non-integer are not supported. */
		abort();
	}
	signedness = integer_type->signedness;
	for (i = 0; i < output->u.sequence.nr_elem; i++) {
		if (signedness) {
			lttng_msgpack_write_signed_integer(writer,
				capture_sequence_element_signed(ptr, integer_type));
		} else {
			lttng_msgpack_write_unsigned_integer(writer,
				capture_sequence_element_unsigned(ptr, integer_type));
		}

		/*
		 * We assume that alignment is smaller or equal to the size.
		 * This currently holds true but if it changes in the future,
		 * we will want to change the pointer arithmetics below to
		 * take into account that the next element might be further
		 * away.
		 */
		assert(integer_type->alignment <= integer_type->size);

		/* Size is in number of bits. */
		ptr += (integer_type->size / CHAR_BIT) ;
	}

	lttng_msgpack_end_array(writer);
}

static
void notification_init(struct lttng_event_notifier_notification *notif,
		struct lttng_event_notifier *event_notifier)
{
	struct lttng_msgpack_writer *writer = &notif->writer;

	notif->event_notifier_token = event_notifier->user_token;
	notif->notification_fd = event_notifier->group->notification_fd;
	notif->has_captures = false;

	if (event_notifier->num_captures > 0) {
		lttng_msgpack_writer_init(writer, notif->capture_buf,
				CAPTURE_BUFFER_SIZE);

		lttng_msgpack_begin_array(writer, event_notifier->num_captures);
		notif->has_captures = true;
	}
}

static
void notification_append_capture(
		struct lttng_event_notifier_notification *notif,
		struct lttng_interpreter_output *output)
{
	struct lttng_msgpack_writer *writer = &notif->writer;

	switch (output->type) {
	case LTTNG_INTERPRETER_TYPE_S64:
		lttng_msgpack_write_signed_integer(writer, output->u.s);
		break;
	case LTTNG_INTERPRETER_TYPE_U64:
		lttng_msgpack_write_unsigned_integer(writer, output->u.u);
		break;
	case LTTNG_INTERPRETER_TYPE_DOUBLE:
		lttng_msgpack_write_double(writer, output->u.d);
		break;
	case LTTNG_INTERPRETER_TYPE_STRING:
		lttng_msgpack_write_str(writer, output->u.str.str);
		break;
	case LTTNG_INTERPRETER_TYPE_SEQUENCE:
		capture_sequence(writer, output);
		break;
	case LTTNG_INTERPRETER_TYPE_SIGNED_ENUM:
	case LTTNG_INTERPRETER_TYPE_UNSIGNED_ENUM:
		capture_enum(writer, output);
		break;
	default:
		abort();
	}
}

static
void notification_append_empty_capture(
		struct lttng_event_notifier_notification *notif)
{
	lttng_msgpack_write_nil(&notif->writer);
}

static
void notification_send(struct lttng_event_notifier_notification *notif)
{
	ssize_t ret;
	size_t content_len;
	int iovec_count = 1;
	struct lttng_ust_event_notifier_notification ust_notif;
	struct iovec iov[2];

	assert(notif);

	ust_notif.token = notif->event_notifier_token;

	/*
	 * Prepare sending the notification from multiple buffers using an
	 * array of `struct iovec`. The first buffer of the vector is
	 * notification structure itself and is always present.
	 */
	iov[0].iov_base = &ust_notif;
	iov[0].iov_len = sizeof(ust_notif);

	if (notif->has_captures) {
		/*
		 * If captures were requested, the second buffer of the array
		 * is the capture buffer.
		 */
		assert(notif->writer.buffer);
		content_len = notif->writer.write_pos - notif->writer.buffer;

		assert(content_len > 0 && content_len <= CAPTURE_BUFFER_SIZE);

		iov[1].iov_base = notif->capture_buf;
		iov[1].iov_len = content_len;

		iovec_count++;
	} else {
		content_len = 0;
	}

	/*
	 * Update the capture buffer size so that receiver of the buffer will
	 * know how much to expect.
	 */
	ust_notif.capture_buf_size = content_len;

	/* Send all the buffers. */
	ret = patient_writev(notif->notification_fd, iov, iovec_count);
	if (ret == -1) {
		if (errno == EAGAIN) {
			DBG("Cannot send event notifier notification without blocking: %s",
				strerror(errno));
		} else {
			DBG("Error to sending event notifier notification: %s",
				strerror(errno));
			abort();
		}
	}
}

void lttng_event_notifier_notification_send(struct lttng_event_notifier *event_notifier,
		const char *stack_data)
{
	/*
	 * This function is called from the probe, we must do dynamic
	 * allocation in this context.
	 */
	struct lttng_event_notifier_notification notif = {0};

	notification_init(&notif, event_notifier);

	if (caa_unlikely(!cds_list_empty(&event_notifier->capture_bytecode_runtime_head))) {
		struct lttng_bytecode_runtime *capture_bc_runtime;

		/*
		 * Iterate over all the capture bytecodes. If the interpreter
		 * functions returns successfully, append the value of the
		 * `output` parameter to the capture buffer. If the interpreter
		 * fails, append an empty capture to the buffer.
		 */
		cds_list_for_each_entry(capture_bc_runtime,
				&event_notifier->capture_bytecode_runtime_head, node) {
			struct lttng_interpreter_output output;

			if (capture_bc_runtime->interpreter_funcs.capture(capture_bc_runtime,
					stack_data, &output) & LTTNG_INTERPRETER_RECORD_FLAG)
				notification_append_capture(&notif, &output);
			else
				notification_append_empty_capture(&notif);
		}
	}

	/*
	 * Send the notification (including the capture buffer) to the
	 * sessiond.
	 */
	notification_send(&notif);
}
