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
#include <common/ust-context-provider.h>
#include <lttng/urcu/pointer.h>
#include <lttng/urcu/urcu-ust.h>
#include "common/logging.h"
#include "common/macros.h"
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include "common/tracepoint.h"

#include "context-internal.h"

/*
 * The filter implementation requires that two consecutive "get" for the
 * same context performed by the same thread return the same result.
 */

int lttng_find_context(struct lttng_ust_ctx *ctx, const char *name)
{
	unsigned int i;
	const char *subname;

	if (!ctx)
		return 0;
	if (strncmp(name, "$ctx.", strlen("$ctx.")) == 0) {
		subname = name + strlen("$ctx.");
	} else {
		subname = name;
	}
	for (i = 0; i < ctx->nr_fields; i++) {
		/* Skip allocated (but non-initialized) contexts */
		if (!ctx->fields[i].event_field->name)
			continue;
		if (!strcmp(ctx->fields[i].event_field->name, subname))
			return 1;
	}
	return 0;
}

int lttng_get_context_index(struct lttng_ust_ctx *ctx, const char *name)
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
		if (!ctx->fields[i].event_field->name)
			continue;
		if (!strcmp(ctx->fields[i].event_field->name, subname))
			return i;
	}
	return -1;
}

static int lttng_find_context_provider(struct lttng_ust_ctx *ctx, const char *name)
{
	unsigned int i;

	for (i = 0; i < ctx->nr_fields; i++) {
		/* Skip allocated (but non-initialized) contexts */
		if (!ctx->fields[i].event_field->name)
			continue;
		if (!strncmp(ctx->fields[i].event_field->name, name,
				strlen(name)))
			return 1;
	}
	return 0;
}

/*
 * Note: as we append context information, the pointer location may change.
 * lttng_ust_context_add_field leaves the new last context initialized to NULL.
 */
static
int lttng_ust_context_add_field(struct lttng_ust_ctx **ctx_p)
{
	struct lttng_ust_ctx *ctx;

	if (!*ctx_p) {
		*ctx_p = zmalloc(sizeof(struct lttng_ust_ctx));
		if (!*ctx_p)
			return -ENOMEM;
		(*ctx_p)->largest_align = 1;
	}
	ctx = *ctx_p;
	if (ctx->nr_fields + 1 > ctx->allocated_fields) {
		struct lttng_ust_ctx_field *new_fields;

		ctx->allocated_fields = max_t(size_t, 1, 2 * ctx->allocated_fields);
		new_fields = zmalloc(ctx->allocated_fields * sizeof(*new_fields));
		if (!new_fields)
			return -ENOMEM;
		/* Copy elements */
		if (ctx->fields)
			memcpy(new_fields, ctx->fields, sizeof(*ctx->fields) * ctx->nr_fields);
		free(ctx->fields);
		ctx->fields = new_fields;
	}
	ctx->nr_fields++;
	return 0;
}

static size_t get_type_max_align(const struct lttng_ust_type_common *type)
{
	switch (type->type) {
	case lttng_ust_type_integer:
		return lttng_ust_get_type_integer(type)->alignment;
	case lttng_ust_type_string:
		return CHAR_BIT;
	case lttng_ust_type_dynamic:
		return 0;
	case lttng_ust_type_enum:
		return get_type_max_align(lttng_ust_get_type_enum(type)->container_type);
	case lttng_ust_type_array:
		return max_t(size_t, get_type_max_align(lttng_ust_get_type_array(type)->elem_type),
				lttng_ust_get_type_array(type)->alignment);
	case lttng_ust_type_sequence:
		return max_t(size_t, get_type_max_align(lttng_ust_get_type_sequence(type)->elem_type),
				lttng_ust_get_type_sequence(type)->alignment);
	case lttng_ust_type_struct:
	{
		unsigned int i;
		size_t field_align = 0;
		const struct lttng_ust_type_struct *struct_type = lttng_ust_get_type_struct(type);

		for (i = 0; i < struct_type->nr_fields; i++) {
			field_align = max_t(size_t,
				get_type_max_align(struct_type->fields[i]->type),
				field_align);
		}
		return field_align;
	}
	default:
		WARN_ON_ONCE(1);
		return 0;
	}
}

/*
 * lttng_context_update() should be called at least once between context
 * modification and trace start.
 */
static
void lttng_context_update(struct lttng_ust_ctx *ctx)
{
	int i;
	size_t largest_align = 8;	/* in bits */

	for (i = 0; i < ctx->nr_fields; i++) {
		size_t field_align = 8;

		field_align = get_type_max_align(ctx->fields[i].event_field->type);
		largest_align = max_t(size_t, largest_align, field_align);
	}
	ctx->largest_align = largest_align >> 3;	/* bits to bytes */
}

int lttng_ust_context_append_rcu(struct lttng_ust_ctx **ctx_p,
		const struct lttng_ust_ctx_field *f)
{
	struct lttng_ust_ctx *old_ctx = *ctx_p, *new_ctx = NULL;
	struct lttng_ust_ctx_field *new_fields = NULL;
	int ret;

	if (old_ctx) {
		new_ctx = zmalloc(sizeof(struct lttng_ust_ctx));
		if (!new_ctx)
			return -ENOMEM;
		*new_ctx = *old_ctx;
		new_fields = zmalloc(new_ctx->allocated_fields * sizeof(*new_fields));
		if (!new_fields) {
			free(new_ctx);
			return -ENOMEM;
		}
		/* Copy elements */
		memcpy(new_fields, old_ctx->fields,
				sizeof(*old_ctx->fields) * old_ctx->nr_fields);
		new_ctx->fields = new_fields;
	}
	ret = lttng_ust_context_add_field(&new_ctx);
	if (ret) {
		free(new_fields);
		free(new_ctx);
		return ret;
	}
	new_ctx->fields[new_ctx->nr_fields - 1] = *f;
	lttng_context_update(new_ctx);
	lttng_ust_rcu_assign_pointer(*ctx_p, new_ctx);
	lttng_ust_urcu_synchronize_rcu();
	if (old_ctx) {
		free(old_ctx->fields);
		free(old_ctx);
	}
	return 0;
}

int lttng_ust_context_append(struct lttng_ust_ctx **ctx_p,
		const struct lttng_ust_ctx_field *f)
{
	int ret;

	ret = lttng_ust_context_add_field(ctx_p);
	if (ret)
		return ret;
	(*ctx_p)->fields[(*ctx_p)->nr_fields - 1] = *f;
	lttng_context_update(*ctx_p);
	return 0;
}

void lttng_destroy_context(struct lttng_ust_ctx *ctx)
{
	int i;

	if (!ctx)
		return;
	for (i = 0; i < ctx->nr_fields; i++) {
		if (ctx->fields[i].destroy)
			ctx->fields[i].destroy(ctx->fields[i].priv);
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
int lttng_ust_context_set_provider_rcu(struct lttng_ust_ctx **_ctx,
		const char *name,
		size_t (*get_size)(void *priv, struct lttng_ust_probe_ctx *probe_ctx,
			size_t offset),
		void (*record)(void *priv, struct lttng_ust_probe_ctx *probe_ctx,
			struct lttng_ust_ring_buffer_ctx *ctx,
			struct lttng_ust_channel_buffer *chan),
		void (*get_value)(void *priv, struct lttng_ust_probe_ctx *probe_ctx,
			struct lttng_ust_ctx_value *value))
{
	int i, ret;
	struct lttng_ust_ctx *ctx = *_ctx, *new_ctx;
	struct lttng_ust_ctx_field *new_fields;

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
	/* Copy elements */
	memcpy(new_fields, ctx->fields,
		sizeof(*new_fields) * ctx->allocated_fields);
	for (i = 0; i < ctx->nr_fields; i++) {
		if (strncmp(new_fields[i].event_field->name,
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

int lttng_context_init_all(struct lttng_ust_ctx **ctx)
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
