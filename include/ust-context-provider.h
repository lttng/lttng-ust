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

/*
 * Context value
 *
 * IMPORTANT: this structure is part of the ABI between the probe and
 * UST. Additional selectors may be added in the future, mapping to new
 * union fields, which means the overall size of this structure may
 * increase. This means this structure should never be nested within a
 * public structure interface, nor embedded in an array.
 */

struct lttng_ust_ctx_value {
	enum lttng_ust_dynamic_type sel;	/* Type selector */
	union {
		int64_t s64;
		uint64_t u64;
		const char *str;
		double d;
	} u;
};

/*
 * Context field
 *
 * IMPORTANT: this structure is part of the ABI between the probe and
 * UST. Fields need to be only added at the end, never reordered, never
 * removed.
 *
 * The field @struct_size should be used to determine the size of the
 * structure. It should be queried before using additional fields added
 * at the end of the structure.
 */

struct lttng_ust_ctx_field {
	uint32_t struct_size;
	void *priv;

	struct lttng_ust_event_field *event_field;
	size_t (*get_size)(struct lttng_ust_ctx_field *field, size_t offset);
	void (*record)(struct lttng_ust_ctx_field *field,
		       struct lttng_ust_lib_ring_buffer_ctx *ctx,
		       struct lttng_channel *chan);
	void (*get_value)(struct lttng_ust_ctx_field *field,
			 struct lttng_ust_ctx_value *value);
	void (*destroy)(struct lttng_ust_ctx_field *field);
	char *field_name;	/* Has ownership, dynamically allocated. */

	/* End of base ABI. Fields below should be used after checking struct_size. */
};

/*
 * All context fields for a given event/channel
 *
 * IMPORTANT: this structure is part of the ABI between the probe and
 * UST. Fields need to be only added at the end, never reordered, never
 * removed.
 *
 * The field @struct_size should be used to determine the size of the
 * structure. It should be queried before using additional fields added
 * at the end of the structure.
 */

struct lttng_ust_ctx {
	uint32_t struct_size;

	struct lttng_ust_ctx_field **fields;
	unsigned int nr_fields;
	unsigned int allocated_fields;
	unsigned int largest_align;

	/* End of base ABI. Fields below should be used after checking struct_size. */
};

/*
 * Context provider
 *
 * IMPORTANT: this structure is part of the ABI between the probe and
 * UST. Fields need to be only added at the end, never reordered, never
 * removed.
 *
 * The field @struct_size should be used to determine the size of the
 * structure. It should be queried before using additional fields added
 * at the end of the structure.
 */

struct lttng_ust_context_provider {
	uint32_t struct_size;

	char *name;
	size_t (*get_size)(struct lttng_ust_ctx_field *field, size_t offset);
	void (*record)(struct lttng_ust_ctx_field *field,
		       struct lttng_ust_lib_ring_buffer_ctx *ctx,
		       struct lttng_channel *chan);
	void (*get_value)(struct lttng_ust_ctx_field *field,
			 struct lttng_ust_ctx_value *value);
	struct cds_hlist_node node;

	/* End of base ABI. Fields below should be used after checking struct_size. */
};

int lttng_ust_context_provider_register(struct lttng_ust_context_provider *provider);
void lttng_ust_context_provider_unregister(struct lttng_ust_context_provider *provider);

void lttng_ust_context_set_session_provider(const char *name,
		size_t (*get_size)(struct lttng_ust_ctx_field *field, size_t offset),
		void (*record)(struct lttng_ust_ctx_field *field,
			struct lttng_ust_lib_ring_buffer_ctx *ctx,
			struct lttng_channel *chan),
		void (*get_value)(struct lttng_ust_ctx_field *field,
			struct lttng_ust_ctx_value *value));

int lttng_ust_add_app_context_to_ctx_rcu(const char *name, struct lttng_ust_ctx **ctx);
int lttng_ust_context_set_provider_rcu(struct lttng_ust_ctx **_ctx,
		const char *name,
		size_t (*get_size)(struct lttng_ust_ctx_field *field, size_t offset),
		void (*record)(struct lttng_ust_ctx_field *field,
			struct lttng_ust_lib_ring_buffer_ctx *ctx,
			struct lttng_channel *chan),
		void (*get_value)(struct lttng_ust_ctx_field *field,
			struct lttng_ust_ctx_value *value));

#endif /* _LTTNG_UST_CONTEXT_PROVIDER_H */
