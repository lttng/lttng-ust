/*
 * lttng-context.c
 *
 * LTTng UST trace/channel/event context management.
 *
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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


#include <lttng/ust-events.h>
#include <lttng/ust-tracer.h>
#include <usterr-signal-safe.h>
#include <helper.h>
#include <string.h>
#include <assert.h>

/*
 * The filter implementation requires that two consecutive "get" for the
 * same context performed by the same thread return the same result.
 */

/*
 * Static array of contexts, for $ctx filters.
 */
struct lttng_ctx *lttng_static_ctx;

int lttng_find_context(struct lttng_ctx *ctx, const char *name)
{
	unsigned int i;

	for (i = 0; i < ctx->nr_fields; i++) {
		/* Skip allocated (but non-initialized) contexts */
		if (!ctx->fields[i].event_field.name)
			continue;
		if (!strcmp(ctx->fields[i].event_field.name, name))
			return 1;
	}
	return 0;
}

int lttng_get_context_index(struct lttng_ctx *ctx, const char *name)
{
	unsigned int i;

	if (!ctx)
		return -1;
	for (i = 0; i < ctx->nr_fields; i++) {
		/* Skip allocated (but non-initialized) contexts */
		if (!ctx->fields[i].event_field.name)
			continue;
		if (!strcmp(ctx->fields[i].event_field.name, name))
			return i;
	}
	return -1;
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
	}
	free(ctx->fields);
	free(ctx);
}

void lttng_context_init(void)
{
	int ret;

	ret = lttng_add_pthread_id_to_ctx(&lttng_static_ctx);
	if (ret) {
		WARN("Cannot add context lttng_add_pthread_id_to_ctx");
	}
	ret = lttng_add_vtid_to_ctx(&lttng_static_ctx);
	if (ret) {
		WARN("Cannot add context lttng_add_vtid_to_ctx");
	}
	ret = lttng_add_vpid_to_ctx(&lttng_static_ctx);
	if (ret) {
		WARN("Cannot add context lttng_add_vpid_to_ctx");
	}
	ret = lttng_add_procname_to_ctx(&lttng_static_ctx);
	if (ret) {
		WARN("Cannot add context lttng_add_procname_to_ctx");
	}
}

void lttng_context_exit(void)
{
	lttng_destroy_context(lttng_static_ctx);
	lttng_static_ctx = NULL;
}
