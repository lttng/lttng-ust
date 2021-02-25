/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * The context provider feature is part of the ABI and used by the Java jni
 * interface. This header should be moved to the public header directory once
 * some test code and documentation is written.
 */

#ifndef _LTTNG_UST_CONTEXT_PROVIDER_H
#define _LTTNG_UST_CONTEXT_PROVIDER_H

#include <stddef.h>
#include <lttng/ust-events.h>
#include <urcu/hlist.h>

struct lttng_ust_context_provider {
	char *name;
	size_t (*get_size)(struct lttng_ctx_field *field, size_t offset);
	void (*record)(struct lttng_ctx_field *field,
		       struct lttng_ust_lib_ring_buffer_ctx *ctx,
		       struct lttng_channel *chan);
	void (*get_value)(struct lttng_ctx_field *field,
			 struct lttng_ctx_value *value);
	struct cds_hlist_node node;
};

int lttng_ust_context_provider_register(struct lttng_ust_context_provider *provider);
void lttng_ust_context_provider_unregister(struct lttng_ust_context_provider *provider);

int lttng_context_is_app(const char *name);

void lttng_ust_context_set_session_provider(const char *name,
		size_t (*get_size)(struct lttng_ctx_field *field, size_t offset),
		void (*record)(struct lttng_ctx_field *field,
			struct lttng_ust_lib_ring_buffer_ctx *ctx,
			struct lttng_channel *chan),
		void (*get_value)(struct lttng_ctx_field *field,
			struct lttng_ctx_value *value));

int lttng_ust_add_app_context_to_ctx_rcu(const char *name, struct lttng_ctx **ctx);
int lttng_ust_context_set_provider_rcu(struct lttng_ctx **_ctx,
		const char *name,
		size_t (*get_size)(struct lttng_ctx_field *field, size_t offset),
		void (*record)(struct lttng_ctx_field *field,
			struct lttng_ust_lib_ring_buffer_ctx *ctx,
			struct lttng_channel *chan),
		void (*get_value)(struct lttng_ctx_field *field,
			struct lttng_ctx_value *value));
int lttng_context_add_rcu(struct lttng_ctx **ctx_p,
		const struct lttng_ctx_field *f);

#endif /* _LTTNG_UST_CONTEXT_PROVIDER_H */
