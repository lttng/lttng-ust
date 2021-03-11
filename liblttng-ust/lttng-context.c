/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng UST trace/channel/event context management.
 */

#define _LGPL_SOURCE
#include <lttng/ust-events.h>
#include <lttng/ust-tracer.h>
#include <ust-context-provider.h>
#include <lttng/urcu/pointer.h>
#include <lttng/urcu/urcu-ust.h>
#include <usterr-signal-safe.h>
#include <ust-helper.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include "tracepoint-internal.h"

#include "context-internal.h"

/*
 * The filter implementation requires that two consecutive "get" for the
 * same context performed by the same thread return the same result.
 */

int lttng_find_context(struct lttng_ctx *ctx, const char *name)
{
	unsigned int i;
	const char *subname;

	if (strncmp(name, "$ctx.", strlen("$ctx.")) == 0) {
		subname = name + strlen("$ctx.");
	} else {
		subname = name;
	}
	for (i = 0; i < ctx->nr_fields; i++) {
		/* Skip allocated (but non-initialized) contexts */
		if (!ctx->fields[i].event_field.name)
			continue;
		if (!strcmp(ctx->fields[i].event_field.name, subname))
			return 1;
	}
	return 0;
}

int lttng_get_context_index(struct lttng_ctx *ctx, const char *name)
{
	unsigned int i;
	const char *subname;

	if (!ctx)
		return -1;
	if (strncmp(name, "$ctx.", strlen("$ctx.")) == 0) {
		subname = name + strlen("$ctx.");
	} else {
		subname = name;
	}
	for (i = 0; i < ctx->nr_fields; i++) {
		/* Skip allocated (but non-initialized) contexts */
		if (!ctx->fields[i].event_field.name)
			continue;
		if (!strcmp(ctx->fields[i].event_field.name, subname))
			return i;
	}
	return -1;
}

static int lttng_find_context_provider(struct lttng_ctx *ctx, const char *name)
{
	unsigned int i;

	for (i = 0; i < ctx->nr_fields; i++) {
		/* Skip allocated (but non-initialized) contexts */
		if (!ctx->fields[i].event_field.name)
			continue;
		if (!strncmp(ctx->fields[i].event_field.name, name,
				strlen(name)))
			return 1;
	}
	return 0;
}

/*
 * Note: as we append context information, the pointer location may change.
 */
struct lttng_ctx_field *lttng_append_context(struct lttng_ctx **ctx_p)
{
	struct lttng_ctx_field *field;
	struct lttng_ctx *ctx;

	if (!*ctx_p) {
		*ctx_p = zmalloc(sizeof(struct lttng_ctx));
		if (!*ctx_p)
			return NULL;
		(*ctx_p)->largest_align = 1;
	}
	ctx = *ctx_p;
	if (ctx->nr_fields + 1 > ctx->allocated_fields) {
		struct lttng_ctx_field *new_fields;

		ctx->allocated_fields = max_t(size_t, 1, 2 * ctx->allocated_fields);
		new_fields = zmalloc(ctx->allocated_fields * sizeof(struct lttng_ctx_field));
		if (!new_fields)
			return NULL;
		if (ctx->fields)
			memcpy(new_fields, ctx->fields, sizeof(*ctx->fields) * ctx->nr_fields);
		free(ctx->fields);
		ctx->fields = new_fields;
	}
	field = &ctx->fields[ctx->nr_fields];
	ctx->nr_fields++;
	return field;
}

int lttng_context_add_rcu(struct lttng_ctx **ctx_p,
		const struct lttng_ctx_field *f)
{
	struct lttng_ctx *old_ctx = *ctx_p, *new_ctx = NULL;
	struct lttng_ctx_field *new_fields = NULL;
	struct lttng_ctx_field *nf;

	if (old_ctx) {
		new_ctx = zmalloc(sizeof(struct lttng_ctx));
		if (!new_ctx)
			return -ENOMEM;
		*new_ctx = *old_ctx;
		new_fields = zmalloc(new_ctx->allocated_fields
				* sizeof(struct lttng_ctx_field));
		if (!new_fields) {
			free(new_ctx);
			return -ENOMEM;
		}
		memcpy(new_fields, old_ctx->fields,
				sizeof(*old_ctx->fields) * old_ctx->nr_fields);
		new_ctx->fields = new_fields;
	}
	nf = lttng_append_context(&new_ctx);
	if (!nf) {
		free(new_fields);
		free(new_ctx);
		return -ENOMEM;
	}
	*nf = *f;
	lttng_context_update(new_ctx);
	lttng_ust_rcu_assign_pointer(*ctx_p, new_ctx);
	lttng_ust_urcu_synchronize_rcu();
	if (old_ctx) {
		free(old_ctx->fields);
		free(old_ctx);
	}
	return 0;
}

/*
 * lttng_context_update() should be called at least once between context
 * modification and trace start.
 */
void lttng_context_update(struct lttng_ctx *ctx)
{
	int i;
	size_t largest_align = 8;	/* in bits */

	for (i = 0; i < ctx->nr_fields; i++) {
		struct lttng_type *type;
		size_t field_align = 8;

		type = &ctx->fields[i].event_field.type;
		switch (type->atype) {
		case atype_integer:
			field_align = type->u.integer.alignment;
			break;
		case atype_array_nestable:
		{
			const struct lttng_type *nested_type;

			nested_type = type->u.array_nestable.elem_type;
			switch (nested_type->atype) {
			case atype_integer:
				field_align = nested_type->u.integer.alignment;
				break;
			case atype_string:
				break;

			case atype_array_nestable:
			case atype_sequence_nestable:
			default:
				WARN_ON_ONCE(1);
				break;
			}
			field_align = max_t(size_t, field_align,
					type->u.array_nestable.alignment);
			break;
		}
		case atype_sequence_nestable:
		{
			const struct lttng_type *nested_type;

			nested_type = type->u.sequence_nestable.elem_type;
			switch (nested_type->atype) {
			case atype_integer:
				field_align = nested_type->u.integer.alignment;
				break;

			case atype_string:
				break;

			case atype_array_nestable:
			case atype_sequence_nestable:
			default:
				WARN_ON_ONCE(1);
				break;
			}
			field_align = max_t(size_t, field_align,
					type->u.sequence_nestable.alignment);
			break;
		}
		case atype_string:
			break;
		case atype_dynamic:
			break;
		case atype_enum_nestable:
		default:
			WARN_ON_ONCE(1);
			break;
		}
		largest_align = max_t(size_t, largest_align, field_align);
	}
	ctx->largest_align = largest_align >> 3;	/* bits to bytes */
}

/*
 * Remove last context field.
 */
void lttng_remove_context_field(struct lttng_ctx **ctx_p,
				struct lttng_ctx_field *field)
{
	struct lttng_ctx *ctx;

	ctx = *ctx_p;
	ctx->nr_fields--;
	assert(&ctx->fields[ctx->nr_fields] == field);
	assert(field->field_name == NULL);
	memset(&ctx->fields[ctx->nr_fields], 0, sizeof(struct lttng_ctx_field));
}

void lttng_destroy_context(struct lttng_ctx *ctx)
{
	int i;

	if (!ctx)
		return;
	for (i = 0; i < ctx->nr_fields; i++) {
		if (ctx->fields[i].destroy)
			ctx->fields[i].destroy(&ctx->fields[i]);
		free(ctx->fields[i].field_name);
	}
	free(ctx->fields);
	free(ctx);
}

/*
 * Can be safely performed concurrently with tracing using the struct
 * lttng_ctx. Using RCU update. Needs to match RCU read-side handling of
 * contexts.
 *
 * This does not allow adding, removing, or changing typing of the
 * contexts, since this needs to stay invariant for metadata. However,
 * it allows updating the handlers associated with all contexts matching
 * a provider (by name) while tracing is using it, in a way that ensures
 * a single RCU read-side critical section see either all old, or all
 * new handlers.
 */
int lttng_ust_context_set_provider_rcu(struct lttng_ctx **_ctx,
		const char *name,
		size_t (*get_size)(struct lttng_ctx_field *field, size_t offset),
		void (*record)(struct lttng_ctx_field *field,
			struct lttng_ust_lib_ring_buffer_ctx *ctx,
			struct lttng_channel *chan),
		void (*get_value)(struct lttng_ctx_field *field,
			struct lttng_ctx_value *value))
{
	int i, ret;
	struct lttng_ctx *ctx = *_ctx, *new_ctx;
	struct lttng_ctx_field *new_fields;

	if (!ctx || !lttng_find_context_provider(ctx, name))
		return 0;
	/*
	 * We have at least one instance of context for the provider.
	 */
	new_ctx = zmalloc(sizeof(*new_ctx));
	if (!new_ctx)
		return -ENOMEM;
	*new_ctx = *ctx;
	new_fields = zmalloc(sizeof(*new_fields) * ctx->allocated_fields);
	if (!new_fields) {
		ret = -ENOMEM;
		goto field_error;
	}
	memcpy(new_fields, ctx->fields,
		sizeof(*new_fields) * ctx->allocated_fields);
	for (i = 0; i < ctx->nr_fields; i++) {
		if (strncmp(new_fields[i].event_field.name,
				name, strlen(name)) != 0)
			continue;
		new_fields[i].get_size = get_size;
		new_fields[i].record = record;
		new_fields[i].get_value = get_value;
	}
	new_ctx->fields = new_fields;
	lttng_ust_rcu_assign_pointer(*_ctx, new_ctx);
	lttng_ust_urcu_synchronize_rcu();
	free(ctx->fields);
	free(ctx);
	return 0;

field_error:
	free(new_ctx);
	return ret;
}

int lttng_context_init_all(struct lttng_ctx **ctx)
{
	int ret;

	ret = lttng_add_pthread_id_to_ctx(ctx);
	if (ret) {
		WARN("Cannot add context lttng_add_pthread_id_to_ctx");
		goto error;
	}
	ret = lttng_add_vtid_to_ctx(ctx);
	if (ret) {
		WARN("Cannot add context lttng_add_vtid_to_ctx");
		goto error;
	}
	ret = lttng_add_vpid_to_ctx(ctx);
	if (ret) {
		WARN("Cannot add context lttng_add_vpid_to_ctx");
		goto error;
	}
	ret = lttng_add_procname_to_ctx(ctx);
	if (ret) {
		WARN("Cannot add context lttng_add_procname_to_ctx");
		goto error;
	}
	ret = lttng_add_cpu_id_to_ctx(ctx);
	if (ret) {
		WARN("Cannot add context lttng_add_cpu_id_to_ctx");
		goto error;
	}
	ret = lttng_add_cgroup_ns_to_ctx(ctx);
	if (ret) {
		WARN("Cannot add context lttng_add_cgroup_ns_to_ctx");
		goto error;
	}
	ret = lttng_add_ipc_ns_to_ctx(ctx);
	if (ret) {
		WARN("Cannot add context lttng_add_ipc_ns_to_ctx");
		goto error;
	}
	ret = lttng_add_mnt_ns_to_ctx(ctx);
	if (ret) {
		WARN("Cannot add context lttng_add_mnt_ns_to_ctx");
		goto error;
	}
	ret = lttng_add_net_ns_to_ctx(ctx);
	if (ret) {
		WARN("Cannot add context lttng_add_net_ns_to_ctx");
		goto error;
	}
	ret = lttng_add_pid_ns_to_ctx(ctx);
	if (ret) {
		WARN("Cannot add context lttng_add_pid_ns_to_ctx");
		goto error;
	}
	ret = lttng_add_time_ns_to_ctx(ctx);
	if (ret) {
		WARN("Cannot add context lttng_add_time_ns_to_ctx");
		goto error;
	}
	ret = lttng_add_user_ns_to_ctx(ctx);
	if (ret) {
		WARN("Cannot add context lttng_add_user_ns_to_ctx");
		goto error;
	}
	ret = lttng_add_uts_ns_to_ctx(ctx);
	if (ret) {
		WARN("Cannot add context lttng_add_uts_ns_to_ctx");
		goto error;
	}
	ret = lttng_add_vuid_to_ctx(ctx);
	if (ret) {
		WARN("Cannot add context lttng_add_vuid_to_ctx");
		goto error;
	}
	ret = lttng_add_veuid_to_ctx(ctx);
	if (ret) {
		WARN("Cannot add context lttng_add_veuid_to_ctx");
		goto error;
	}
	ret = lttng_add_vsuid_to_ctx(ctx);
	if (ret) {
		WARN("Cannot add context lttng_add_vsuid_to_ctx");
		goto error;
	}
	ret = lttng_add_vgid_to_ctx(ctx);
	if (ret) {
		WARN("Cannot add context lttng_add_vgid_to_ctx");
		goto error;
	}
	ret = lttng_add_vegid_to_ctx(ctx);
	if (ret) {
		WARN("Cannot add context lttng_add_vegid_to_ctx");
		goto error;
	}
	ret = lttng_add_vsgid_to_ctx(ctx);
	if (ret) {
		WARN("Cannot add context lttng_add_vsgid_to_ctx");
		goto error;
	}
	lttng_context_update(*ctx);
	return 0;

error:
	lttng_destroy_context(*ctx);
	return ret;
}
