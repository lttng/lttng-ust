/*
 * (C) Copyright	2009-2011 -
 * 		Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng UST procname context.
 *
 * Dual LGPL v2.1/GPL v2 license.
 */

#include <sys/prctl.h>
#include <ust/lttng-events.h>
#include <ust/lttng-tracer.h>
#include <ust/ringbuffer-config.h>
#include <assert.h>

#define PROCNAME_LEN	17	/* includes \0 */

/*
 * We cache the result to ensure we don't trigger a system call for
 * each event.
 * Upon exec, procname changes, but exec takes care of throwing away
 * this cached version.
 */
static char cached_procname[17];

static inline
char *wrapper_getprocname(void)
{
	int ret;

	if (unlikely(!cached_procname[0])) {
		ret = prctl(PR_GET_NAME, (unsigned long) cached_procname,
			0, 0, 0);
		assert(!ret);
	}
	return cached_procname;
}

void lttng_context_procname_reset(void)
{
	cached_procname[0] = '\0';
}

static
size_t procname_get_size(size_t offset)
{
	size_t size = 0;

	size += PROCNAME_LEN;
	return size;
}

static
void procname_record(struct lttng_ctx_field *field,
		 struct lttng_ust_lib_ring_buffer_ctx *ctx,
		 struct ltt_channel *chan)
{
	char *procname;

	procname = wrapper_getprocname();
	chan->ops->event_write(ctx, procname, PROCNAME_LEN);
}

int lttng_add_procname_to_ctx(struct lttng_ctx **ctx)
{
	struct lttng_ctx_field *field;

	field = lttng_append_context(ctx);
	if (!field)
		return -ENOMEM;
	if (lttng_find_context(*ctx, "procname")) {
		lttng_remove_context_field(ctx, field);
		return -EEXIST;
	}
	field->event_field.name = "procname";
	field->event_field.type.atype = atype_array;
	field->event_field.type.u.array.elem_type.atype = atype_integer;
	field->event_field.type.u.array.elem_type.u.basic.integer.size = sizeof(char) * CHAR_BIT;
	field->event_field.type.u.array.elem_type.u.basic.integer.alignment = lttng_alignof(char) * CHAR_BIT;
	field->event_field.type.u.array.elem_type.u.basic.integer.signedness = lttng_is_signed_type(char);
	field->event_field.type.u.array.elem_type.u.basic.integer.reverse_byte_order = 0;
	field->event_field.type.u.array.elem_type.u.basic.integer.base = 10;
	field->event_field.type.u.array.elem_type.u.basic.integer.encoding = lttng_encode_UTF8;
	field->event_field.type.u.array.length = PROCNAME_LEN;
	field->get_size = procname_get_size;
	field->record = procname_record;
	return 0;
}
