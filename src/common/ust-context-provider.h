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

#include "common/dynamic-type.h"

struct lttng_ust_registered_context_provider;
struct lttng_ust_probe_ctx;

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

	const char *name;
	size_t (*get_size)(void *priv, struct lttng_ust_probe_ctx *probe_ctx,
			size_t offset);
	void (*record)(void *priv, struct lttng_ust_probe_ctx *probe_ctx,
			struct lttng_ust_ring_buffer_ctx *ctx,
			struct lttng_ust_channel_buffer *chan);
	void (*get_value)(void *priv, struct lttng_ust_probe_ctx *probe_ctx,
			struct lttng_ust_ctx_value *value);
	void *priv;

	/* End of base ABI. Fields below should be used after checking struct_size. */
};

/*
 * Application context callback private data
 *
 * IMPORTANT: this structure is part of the ABI between the probe and
 * UST. Fields need to be only added at the end, never reordered, never
 * removed.
 *
 * The field @struct_size should be used to determine the size of the
 * structure. It should be queried before using additional fields added
 * at the end of the structure.
 */

struct lttng_ust_app_context {
	uint32_t struct_size;

	struct lttng_ust_event_field *event_field;
	char *ctx_name;

	/* End of base ABI. Fields below should be used after checking struct_size. */
};

/*
 * Returns an opaque pointer on success, which must be passed to
 * lttng_ust_context_provider_unregister for unregistration. Returns
 * NULL on error.
 */
struct lttng_ust_registered_context_provider *lttng_ust_context_provider_register(struct lttng_ust_context_provider *provider);

void lttng_ust_context_provider_unregister(struct lttng_ust_registered_context_provider *reg_provider);

#endif /* _LTTNG_UST_CONTEXT_PROVIDER_H */
