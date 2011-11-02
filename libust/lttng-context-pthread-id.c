/*
 * (C) Copyright	2009-2011 -
 * 		Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng UST pthread_id context.
 *
 * Dual LGPL v2.1/GPL v2 license.
 */

#include <pthread.h>
#include <ust/lttng-events.h>
#include <ust/lttng-tracer.h>
#include <ust/ringbuffer-config.h>

static
size_t pthread_id_get_size(size_t offset)
{
	size_t size = 0;

	size += lib_ring_buffer_align(offset, lttng_alignof(unsigned long));
	size += sizeof(unsigned long);
	return size;
}

static
void pthread_id_record(struct lttng_ctx_field *field,
		 struct lttng_ust_lib_ring_buffer_ctx *ctx,
		 struct ltt_channel *chan)
{
	unsigned long pthread_id;

	pthread_id = (unsigned long) pthread_self();
	lib_ring_buffer_align_ctx(ctx, lttng_alignof(pthread_id));
	chan->ops->event_write(ctx, &pthread_id, sizeof(pthread_id));
}

int lttng_add_pthread_id_to_ctx(struct lttng_ctx **ctx)
{
	struct lttng_ctx_field *field;

	field = lttng_append_context(ctx);
	if (!field)
		return -ENOMEM;
	if (lttng_find_context(*ctx, "pthread_id")) {
		lttng_remove_context_field(ctx, field);
		return -EEXIST;
	}
	field->event_field.name = "pthread_id";
	field->event_field.type.atype = atype_integer;
	field->event_field.type.u.basic.integer.size = sizeof(unsigned long) * CHAR_BIT;
	field->event_field.type.u.basic.integer.alignment = lttng_alignof(unsigned long) * CHAR_BIT;
	field->event_field.type.u.basic.integer.signedness = lttng_is_signed_type(unsigned long);
	field->event_field.type.u.basic.integer.reverse_byte_order = 0;
	field->event_field.type.u.basic.integer.base = 10;
	field->event_field.type.u.basic.integer.encoding = lttng_encode_none;
	field->get_size = pthread_id_get_size;
	field->record = pthread_id_record;
	return 0;
}
