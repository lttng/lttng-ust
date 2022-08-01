/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng UST application context provider.
 */

#define _LGPL_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

#include <common/ust-context-provider.h>

#include "context-internal.h"
#include "lttng-tracer-core.h"
#include "common/jhash.h"
#include "context-provider-internal.h"
#include "common/macros.h"
#include "common/tracer.h"

struct lttng_ust_registered_context_provider {
	const struct lttng_ust_context_provider *provider;

	struct cds_hlist_node node;
};

#define CONTEXT_PROVIDER_HT_BITS	12
#define CONTEXT_PROVIDER_HT_SIZE	(1U << CONTEXT_PROVIDER_HT_BITS)
struct context_provider_ht {
	struct cds_hlist_head table[CONTEXT_PROVIDER_HT_SIZE];
};

static struct context_provider_ht context_provider_ht;

static const struct lttng_ust_context_provider *
		lookup_provider_by_name(const char *name)
{
	struct cds_hlist_head *head;
	struct cds_hlist_node *node;
	struct lttng_ust_registered_context_provider *reg_provider;
	uint32_t hash;
	const char *end;
	size_t len;

	/* Lookup using everything before first ':' as key. */
	end = strchr(name, ':');
	if (end)
		len = end - name;
	else
		len = strlen(name);
	hash = jhash(name, len, 0);
	head = &context_provider_ht.table[hash & (CONTEXT_PROVIDER_HT_SIZE - 1)];
	cds_hlist_for_each_entry(reg_provider, node, head, node) {
		if (!strncmp(reg_provider->provider->name, name, len))
			return reg_provider->provider;
	}
	return NULL;
}

struct lttng_ust_registered_context_provider *lttng_ust_context_provider_register(struct lttng_ust_context_provider *provider)
{
	struct lttng_ust_registered_context_provider *reg_provider = NULL;
	struct cds_hlist_head *head;
	size_t name_len = strlen(provider->name);
	uint32_t hash;

	lttng_ust_common_init_thread(0);

	/* Provider name starts with "$app.". */
	if (strncmp("$app.", provider->name, strlen("$app.")) != 0)
		return NULL;
	/* Provider name cannot contain a colon character. */
	if (strchr(provider->name, ':'))
		return NULL;
	if (ust_lock())
		goto end;
	if (lookup_provider_by_name(provider->name))
		goto end;
	reg_provider = zmalloc(sizeof(struct lttng_ust_registered_context_provider));
	if (!reg_provider)
		goto end;
	reg_provider->provider = provider;
	hash = jhash(provider->name, name_len, 0);
	head = &context_provider_ht.table[hash & (CONTEXT_PROVIDER_HT_SIZE - 1)];
	cds_hlist_add_head(&reg_provider->node, head);

	lttng_ust_context_set_session_provider(provider->name,
		provider->get_size, provider->record,
		provider->get_value);

	lttng_ust_context_set_event_notifier_group_provider(provider->name,
		provider->get_size, provider->record,
		provider->get_value);
end:
	ust_unlock();
	return reg_provider;
}

void lttng_ust_context_provider_unregister(struct lttng_ust_registered_context_provider *reg_provider)
{
	lttng_ust_common_init_thread(0);

	if (ust_lock())
		goto end;
	lttng_ust_context_set_session_provider(reg_provider->provider->name,
		lttng_ust_dummy_get_size, lttng_ust_dummy_record,
		lttng_ust_dummy_get_value);

	lttng_ust_context_set_event_notifier_group_provider(reg_provider->provider->name,
		lttng_ust_dummy_get_size, lttng_ust_dummy_record,
		lttng_ust_dummy_get_value);

	cds_hlist_del(&reg_provider->node);
end:
	ust_unlock();
	free(reg_provider);
}

static
void app_context_destroy(void *priv)
{
	struct lttng_ust_app_context *app_ctx = (struct lttng_ust_app_context *) priv;

	free(app_ctx->ctx_name);
	free(app_ctx->event_field);
}

static
const struct lttng_ust_type_common app_ctx_type = {
	.type = lttng_ust_type_dynamic,
};

/*
 * Called with ust mutex held.
 * Add application context to array of context, even if the application
 * context is not currently loaded by application. It will then use the
 * dummy callbacks in that case.
 * Always performed before tracing is started, since it modifies
 * metadata describing the context.
 */
int lttng_ust_add_app_context_to_ctx_rcu(const char *name,
		struct lttng_ust_ctx **ctx)
{
	const struct lttng_ust_context_provider *provider;
	struct lttng_ust_ctx_field new_field = { 0 };
	struct lttng_ust_event_field *event_field = NULL;
	struct lttng_ust_app_context *app_ctx = NULL;
	char *ctx_name;
	int ret;

	if (*ctx && lttng_find_context(*ctx, name))
		return -EEXIST;
	event_field = zmalloc(sizeof(struct lttng_ust_event_field));
	if (!event_field) {
		ret = -ENOMEM;
		goto error_event_field_alloc;
	}
	ctx_name = strdup(name);
	if (!ctx_name) {
		ret = -ENOMEM;
		goto error_field_name_alloc;
	}
	app_ctx = zmalloc(sizeof(struct lttng_ust_app_context));
	if (!app_ctx) {
		ret = -ENOMEM;
		goto error_app_ctx_alloc;
	}
	app_ctx->struct_size = sizeof(struct lttng_ust_app_context);
	app_ctx->event_field = event_field;
	app_ctx->ctx_name = ctx_name;

	event_field->name = ctx_name;
	event_field->type = &app_ctx_type;
	new_field.event_field = event_field;
	/*
	 * If provider is not found, we add the context anyway, but
	 * it will provide a dummy context.
	 */
	provider = lookup_provider_by_name(name);
	if (provider) {
		new_field.get_size = provider->get_size;
		new_field.record = provider->record;
		new_field.get_value = provider->get_value;
	} else {
		new_field.get_size = lttng_ust_dummy_get_size;
		new_field.record = lttng_ust_dummy_record;
		new_field.get_value = lttng_ust_dummy_get_value;
	}
	new_field.priv = app_ctx;
	new_field.destroy = app_context_destroy;
	/*
	 * For application context, add it by expanding
	 * ctx array.
	 */
	ret = lttng_ust_context_append_rcu(ctx, &new_field);
	if (ret) {
		goto error_append;
	}
	return 0;

error_append:
	free(app_ctx);
error_app_ctx_alloc:
	free(ctx_name);
error_field_name_alloc:
	free(event_field);
error_event_field_alloc:
	return ret;
}
