/*
 * (C) Copyright	2009-2011 -
 * 		Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng UST vtid context.
 *
 * Dual LGPL v2.1/GPL v2 license.
 */

#include <sys/types.h>
#include <unistd.h>
#include <lttng/ust-events.h>
#include <lttng/ust-tracer.h>
#include <lttng/ringbuffer-config.h>
#include <lttng/ust-tid.h>

/*
 * We cache the result to ensure we don't trigger a system call for
 * each event.
 */
static __thread pid_t cached_vtid;

/*
 * Upon fork or clone, the TID assigned to our thread is not the same as
 * we kept in cache. Luckily, we are the only thread surviving in the
 * child process, so we can simply clear our cached version.
 */
void lttng_context_vtid_reset(void)
{
	cached_vtid = 0;
}

static
size_t vtid_get_size(size_t offset)
{
	size_t size = 0;

	size += lib_ring_buffer_align(offset, lttng_alignof(pid_t));
	size += sizeof(pid_t);
	return size;
}

static
void vtid_record(struct lttng_ctx_field *field,
		 struct lttng_ust_lib_ring_buffer_ctx *ctx,
		 struct ltt_channel *chan)
{
	if (caa_unlikely(!cached_vtid))
		cached_vtid = gettid();
	lib_ring_buffer_align_ctx(ctx, lttng_alignof(cached_vtid));
	chan->ops->event_write(ctx, &cached_vtid, sizeof(cached_vtid));
}

int lttng_add_vtid_to_ctx(struct lttng_ctx **ctx)
{
	struct lttng_ctx_field *field;

	field = lttng_append_context(ctx);
	if (!field)
		return -ENOMEM;
	if (lttng_find_context(*ctx, "vtid")) {
		lttng_remove_context_field(ctx, field);
		return -EEXIST;
	}
	field->event_field.name = "vtid";
	field->event_field.type.atype = atype_integer;
	field->event_field.type.u.basic.integer.size = sizeof(pid_t) * CHAR_BIT;
	field->event_field.type.u.basic.integer.alignment = lttng_alignof(pid_t) * CHAR_BIT;
	field->event_field.type.u.basic.integer.signedness = lttng_is_signed_type(pid_t);
	field->event_field.type.u.basic.integer.reverse_byte_order = 0;
	field->event_field.type.u.basic.integer.base = 10;
	field->event_field.type.u.basic.integer.encoding = lttng_encode_none;
	field->get_size = vtid_get_size;
	field->record = vtid_record;
	return 0;
}
