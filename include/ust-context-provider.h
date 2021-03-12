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

#include "ust-dynamic-type.h"

struct lttng_ctx_value {
	enum lttng_ust_dynamic_type sel;
	union {
		int64_t s64;
		uint64_t u64;
		const char *str;
		double d;
	} u;
};

struct lttng_perf_counter_field;

#define LTTNG_UST_CTX_FIELD_PADDING	40
struct lttng_ctx_field {
	struct lttng_ust_event_field event_field;
	size_t (*get_size)(struct lttng_ctx_field *field, size_t offset);
	void (*record)(struct lttng_ctx_field *field,
		       struct lttng_ust_lib_ring_buffer_ctx *ctx,
		       struct lttng_channel *chan);
	void (*get_value)(struct lttng_ctx_field *field,
			 struct lttng_ctx_value *value);
	union {
		struct lttng_perf_counter_field *perf_counter;
		char padding[LTTNG_UST_CTX_FIELD_PADDING];
	} u;
	void (*destroy)(struct lttng_ctx_field *field);
	char *field_name;	/* Has ownership, dynamically allocated. */
};

#define LTTNG_UST_CTX_PADDING	20
struct lttng_ctx {
	struct lttng_ctx_field *fields;
	unsigned int nr_fields;
	unsigned int allocated_fields;
	unsigned int largest_align;
	char padding[LTTNG_UST_CTX_PADDING];
};

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

#endif /* _LTTNG_UST_CONTEXT_PROVIDER_H */
