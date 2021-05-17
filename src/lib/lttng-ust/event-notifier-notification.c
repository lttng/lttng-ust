/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 */

#define _LGPL_SOURCE

#include <assert.h>
#include <errno.h>
#include <limits.h>

#include <lttng/ust-endian.h>
#include "common/logging.h"
#include <urcu/rculist.h>

#include "lttng-tracer-core.h"
#include "lib/lttng-ust/events.h"
#include "common/msgpack/msgpack.h"
#include "lttng-bytecode.h"
#include "common/patient.h"

/*
 * We want this write to be atomic AND non-blocking, meaning that we
 * want to write either everything OR nothing.
 * According to `pipe(7)`, writes that are less than `PIPE_BUF` bytes must be
 * atomic, so we bound the capture buffer size to the `PIPE_BUF` minus the size
 * of the notification struct we are sending alongside the capture buffer.
 */
#define CAPTURE_BUFFER_SIZE \
	(PIPE_BUF - sizeof(struct lttng_ust_abi_event_notifier_notification) - 1)

#define MSG_WRITE_NIL_LEN 1

struct lttng_event_notifier_notification {
	int notification_fd;
	uint64_t event_notifier_token;
	uint8_t capture_buf[CAPTURE_BUFFER_SIZE];
	struct lttng_msgpack_writer writer;
	bool has_captures;
};

static
int capture_enum(struct lttng_msgpack_writer *writer,
		struct lttng_interpreter_output *output)
{
	int ret;

	ret = lttng_msgpack_begin_map(writer, 2);
	if (ret) {
		goto end;
	}
	ret = lttng_msgpack_write_str(writer, "type");
	if (ret) {
		goto end;
	}
	ret = lttng_msgpack_write_str(writer, "enum");
	if (ret) {
		goto end;
	}
	ret = lttng_msgpack_write_str(writer, "value");
	if (ret) {
		goto end;
	}

	switch (output->type) {
	case LTTNG_INTERPRETER_TYPE_SIGNED_ENUM:
		ret = lttng_msgpack_write_signed_integer(writer, output->u.s);
		if (ret) {
			goto end;
		}
		break;
	case LTTNG_INTERPRETER_TYPE_UNSIGNED_ENUM:
		ret = lttng_msgpack_write_signed_integer(writer, output->u.u);
		if (ret) {
			goto end;
		}
		break;
	default:
		CRIT("Unknown enum output type\n");
		ret = -1;
		goto end;
	}

	ret = lttng_msgpack_end_map(writer);
end:
	return ret;
}

static
int64_t capture_sequence_element_signed(uint8_t *ptr,
		const struct lttng_ust_type_integer *integer_type)
{
	int64_t value;
	unsigned int size = integer_type->size;
	bool byte_order_reversed = integer_type->reverse_byte_order;

	switch (size) {
	case 8:
		value = *ptr;
		break;
	case 16:
	{
		int16_t tmp;
		tmp = *(int16_t *) ptr;
		if (byte_order_reversed)
			tmp = lttng_ust_bswap_16(tmp);

		value = tmp;
		break;
	}
	case 32:
	{
		int32_t tmp;
		tmp = *(int32_t *) ptr;
		if (byte_order_reversed)
			tmp = lttng_ust_bswap_32(tmp);

		value = tmp;
		break;
	}
	case 64:
	{
		int64_t tmp;
		tmp = *(int64_t *) ptr;
		if (byte_order_reversed)
			tmp = lttng_ust_bswap_64(tmp);

		value = tmp;
		break;
	}
	default:
		CRIT("Unknown sequence element size\n");
		value = 0;
	}

	return value;
}

static
uint64_t capture_sequence_element_unsigned(uint8_t *ptr,
		const struct lttng_ust_type_integer *integer_type)
{
	uint64_t value;
	unsigned int size = integer_type->size;
	bool byte_order_reversed = integer_type->reverse_byte_order;

	switch (size) {
	case 8:
		value = *ptr;
		break;
	case 16:
	{
		uint16_t tmp;
		tmp = *(uint16_t *) ptr;
		if (byte_order_reversed)
			tmp = lttng_ust_bswap_16(tmp);

		value = tmp;
		break;
	}
	case 32:
	{
		uint32_t tmp;
		tmp = *(uint32_t *) ptr;
		if (byte_order_reversed)
			tmp = lttng_ust_bswap_32(tmp);

		value = tmp;
		break;
	}
	case 64:
	{
		uint64_t tmp;
		tmp = *(uint64_t *) ptr;
		if (byte_order_reversed)
			tmp = lttng_ust_bswap_64(tmp);

		value = tmp;
		break;
	}
	default:
		CRIT("Unknown sequence element size\n");
		value = 0;
	}

	return value;
}

static
int capture_sequence(struct lttng_msgpack_writer *writer,
		struct lttng_interpreter_output *output)
{
	const struct lttng_ust_type_integer *integer_type;
	const struct lttng_ust_type_common *nested_type;
	uint8_t *ptr;
	bool signedness;
	int i, ret;

	ret = lttng_msgpack_begin_array(writer, output->u.sequence.nr_elem);
	if (ret) {
		goto end;
	}
	ptr = (uint8_t *) output->u.sequence.ptr;
	nested_type = output->u.sequence.nested_type;
	switch (nested_type->type) {
	case lttng_ust_type_integer:
		integer_type = lttng_ust_get_type_integer(nested_type);
		break;
	case lttng_ust_type_enum:
		/* Treat enumeration as an integer. */
		integer_type = lttng_ust_get_type_integer(lttng_ust_get_type_enum(nested_type)->container_type);
		break;
	default:
		CRIT("Capture of array of non-integer are not supported\n");
		ret = -1;
		goto end;
	}
	signedness = integer_type->signedness;
	for (i = 0; i < output->u.sequence.nr_elem; i++) {
		if (signedness) {
			ret = lttng_msgpack_write_signed_integer(writer,
				capture_sequence_element_signed(ptr, integer_type));
		} else {
			ret = lttng_msgpack_write_unsigned_integer(writer,
				capture_sequence_element_unsigned(ptr, integer_type));
		}
		if (ret) {
			goto end;
		}

		/*
		 * We assume that alignment is smaller or equal to the size.
		 * This currently holds true but if it changes in the future,
		 * we will want to change the pointer arithmetic below to
		 * take into account that the next element might be further
		 * away.
		 */
		assert(integer_type->alignment <= integer_type->size);

		/* Size is in number of bits. */
		ptr += (integer_type->size / CHAR_BIT) ;
	}

	ret = lttng_msgpack_end_array(writer);
end:
	return ret;
}

static
int notification_init(struct lttng_event_notifier_notification *notif,
		const struct lttng_ust_event_notifier *event_notifier)
{
	struct lttng_msgpack_writer *writer = &notif->writer;
	int ret = 0;

	notif->event_notifier_token = event_notifier->priv->parent.user_token;
	notif->notification_fd = event_notifier->priv->group->notification_fd;
	notif->has_captures = false;

	if (event_notifier->priv->num_captures > 0) {
		lttng_msgpack_writer_init(writer, notif->capture_buf,
				CAPTURE_BUFFER_SIZE);

		ret = lttng_msgpack_begin_array(writer, event_notifier->priv->num_captures);
		if (ret) {
			goto end;
		}
		notif->has_captures = true;
	}
end:
	return ret;
}

static
int notification_append_capture(
		struct lttng_event_notifier_notification *notif,
		struct lttng_interpreter_output *output)
{
	struct lttng_msgpack_writer *writer = &notif->writer;
	int ret;

	switch (output->type) {
	case LTTNG_INTERPRETER_TYPE_S64:
		ret = lttng_msgpack_write_signed_integer(writer, output->u.s);
		break;
	case LTTNG_INTERPRETER_TYPE_U64:
		ret = lttng_msgpack_write_unsigned_integer(writer, output->u.u);
		break;
	case LTTNG_INTERPRETER_TYPE_DOUBLE:
		ret = lttng_msgpack_write_double(writer, output->u.d);
		break;
	case LTTNG_INTERPRETER_TYPE_STRING:
		ret = lttng_msgpack_write_str(writer, output->u.str.str);
		break;
	case LTTNG_INTERPRETER_TYPE_SEQUENCE:
		ret = capture_sequence(writer, output);
		break;
	case LTTNG_INTERPRETER_TYPE_SIGNED_ENUM:
	case LTTNG_INTERPRETER_TYPE_UNSIGNED_ENUM:
		ret = capture_enum(writer, output);
		break;
	default:
		CRIT("Unknown capture output type\n");
		ret = -1;
	}
	return ret;
}

static
int notification_append_empty_capture(
		struct lttng_event_notifier_notification *notif)
{
	return lttng_msgpack_write_nil(&notif->writer);
}

static void record_error(const struct lttng_ust_event_notifier *event_notifier)
{
	struct lttng_event_notifier_group *event_notifier_group =
			event_notifier->priv->group;
	struct lttng_ust_channel_counter *error_counter;
	size_t dimension_index[1];
	int ret;

	error_counter = CMM_LOAD_SHARED(event_notifier_group->error_counter);
	/*
	 * load-acquire paired with store-release orders creation of the
	 * error counter and setting error_counter_len before the
	 * error_counter is used.
	 * Currently a full memory barrier is used, which could be
	 * turned into acquire-release barriers.
	 */
	cmm_smp_mb();
	/* This group may not have an error counter attached to it. */
	if (!error_counter)
		return;

	dimension_index[0] = event_notifier->priv->error_counter_index;
	ret = event_notifier_group->error_counter->ops->priv->counter_add(
			error_counter, dimension_index, 1);
	if (ret)
		WARN_ON_ONCE(1);
}

static
void notification_send(struct lttng_event_notifier_notification *notif,
		const struct lttng_ust_event_notifier *event_notifier)
{
	ssize_t ret;
	size_t content_len;
	int iovec_count = 1;
	struct lttng_ust_abi_event_notifier_notification ust_notif = {0};
	struct iovec iov[2];

	assert(notif);

	ust_notif.token = event_notifier->priv->parent.user_token;

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
	ret = ust_patient_writev(notif->notification_fd, iov, iovec_count);
	if (ret == -1) {
		if (errno == EAGAIN) {
			record_error(event_notifier);
			DBG("Cannot send event_notifier notification without blocking: %s",
				strerror(errno));
		} else {
			DBG("Error to sending event notifier notification: %s",
				strerror(errno));
			abort();
		}
	}
}

/*
 * Validate that the buffer has enough room to hold empty capture fields.
 */
static
bool validate_buffer_len(struct lttng_event_notifier_notification *notif, size_t captures_left)
{
	if (notif->writer.end_write_pos - notif->writer.write_pos < MSG_WRITE_NIL_LEN * captures_left)
		return false;
	return true;
}

void lttng_event_notifier_notification_send(
		const struct lttng_ust_event_notifier *event_notifier,
		const char *stack_data,
		struct lttng_ust_probe_ctx *probe_ctx,
		struct lttng_ust_notification_ctx *notif_ctx)
{
	/*
	 * This function is called from the probe, we must do dynamic
	 * allocation in this context.
	 */
	struct lttng_event_notifier_notification notif = {0};
	size_t captures_left;

	if (notification_init(&notif, event_notifier))
		goto error;

	captures_left = event_notifier->priv->num_captures;
	if (!validate_buffer_len(&notif, captures_left))
		goto error;

	if (caa_unlikely(notif_ctx->eval_capture)) {
		struct lttng_ust_bytecode_runtime *capture_bc_runtime;

		/*
		 * Iterate over all the capture bytecodes. If the interpreter
		 * functions returns successfully, append the value of the
		 * `output` parameter to the capture buffer. If the interpreter
		 * fails, append an empty capture to the buffer.
		 */
		cds_list_for_each_entry_rcu(capture_bc_runtime,
				&event_notifier->priv->capture_bytecode_runtime_head, node) {
			struct lttng_interpreter_output output;
			uint8_t *save_pos;
			int ret = -1;

			lttng_msgpack_save_writer_pos(&notif.writer, &save_pos);
			if (capture_bc_runtime->interpreter_func(capture_bc_runtime,
					stack_data, probe_ctx, &output) == LTTNG_UST_BYTECODE_INTERPRETER_OK)
				ret = notification_append_capture(&notif, &output);
			if (ret || !validate_buffer_len(&notif, captures_left)) {
				/*
				 * On append capture error or if the generated
				 * buffer data would not leave enough room to
				 * write empty capture fields for the remaining
				 * fields, skip the field capture by restoring
				 * the msgpack writer position and writing an
				 * empty capture field.
				 */
				lttng_msgpack_restore_writer_pos(&notif.writer, save_pos);
				ret = notification_append_empty_capture(&notif);
				if (ret)
					CRIT("Not enough space for empty capture field\n");
			}
		}
	}

	if (notif.has_captures && lttng_msgpack_end_array(&notif.writer))
		goto error;

	/*
	 * Send the notification (including the capture buffer) to the
	 * sessiond.
	 */
	notification_send(&notif, event_notifier);
	return;

error:
	record_error(event_notifier);
	return;
}
