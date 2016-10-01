/*
 * lttng-context-provider.c
 *
 * LTTng UST application context provider.
 *
 * Copyright (C) 2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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
#include <sys/types.h>
#include <unistd.h>
#include <lttng/ust-context-provider.h>
#include "lttng-tracer-core.h"
#include "jhash.h"
#include <helper.h>

#define CONTEXT_PROVIDER_HT_BITS	12
#define CONTEXT_PROVIDER_HT_SIZE	(1U << CONTEXT_PROVIDER_HT_BITS)
struct context_provider_ht {
	struct cds_hlist_head table[CONTEXT_PROVIDER_HT_SIZE];
};

static struct context_provider_ht context_provider_ht;

static struct lttng_ust_context_provider *
		lookup_provider_by_name(const char *name)
{
	struct cds_hlist_head *head;
	struct cds_hlist_node *node;
	struct lttng_ust_context_provider *provider;
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
	cds_hlist_for_each_entry(provider, node, head, node) {
		if (!strncmp(provider->name, name, len))
			return provider;
	}
	return NULL;
}

int lttng_ust_context_provider_register(struct lttng_ust_context_provider *provider)
{
	struct cds_hlist_head *head;
	size_t name_len = strlen(provider->name);
	uint32_t hash;
	int ret = 0;

	lttng_ust_fixup_tls();

	/* Provider name starts with "$app.". */
	if (strncmp("$app.", provider->name, strlen("$app.") != 0))
		return -EINVAL;
	/* Provider name cannot contain a column character. */
	if (strchr(provider->name, ':'))
		return -EINVAL;
	if (ust_lock()) {
		ret = -EBUSY;
		goto end;
	}
	if (lookup_provider_by_name(provider->name)) {
		ret = -EBUSY;
		goto end;
	}
	hash = jhash(provider->name, name_len, 0);
	head = &context_provider_ht.table[hash & (CONTEXT_PROVIDER_HT_SIZE - 1)];
	cds_hlist_add_head(&provider->node, head);
	lttng_ust_context_set_session_provider(provider->name,
		provider->get_size, provider->record,
		provider->get_value);
end:
	ust_unlock();
	return ret;
}

void lttng_ust_context_provider_unregister(struct lttng_ust_context_provider *provider)
{
	lttng_ust_fixup_tls();

	if (ust_lock())
		goto end;
	lttng_ust_context_set_session_provider(provider->name,
		lttng_ust_dummy_get_size, lttng_ust_dummy_record,
		lttng_ust_dummy_get_value);
	cds_hlist_del(&provider->node);
end:
	ust_unlock();
}

/*
 * Called with ust mutex held.
 * Add application context to array of context, even if the application
 * context is not currently loaded by application. It will then use the
 * dummy callbacks in that case.
 * Always performed before tracing is started, since it modifies
 * metadata describing the context.
 */
int lttng_ust_add_app_context_to_ctx_rcu(const char *name,
		struct lttng_ctx **ctx)
{
	struct lttng_ust_context_provider *provider;
	struct lttng_ctx_field new_field;
	int ret;

	if (*ctx && lttng_find_context(*ctx, name))
		return -EEXIST;
	/*
	 * For application context, add it by expanding
	 * ctx array.
	 */
	memset(&new_field, 0, sizeof(new_field));
	new_field.field_name = strdup(name);
	if (!new_field.field_name)
		return -ENOMEM;
	new_field.event_field.name = new_field.field_name;
	new_field.event_field.type.atype = atype_dynamic;
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
	ret = lttng_context_add_rcu(ctx, &new_field);
	if (ret) {
		free(new_field.field_name);
		return ret;
	}
	return 0;
}
