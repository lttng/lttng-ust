/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2019 Francis Deslauriers <francis.deslauriers@efficios.com>
 */

#ifndef _LTTNG_UST_CONTEXT_PROVIDER_INTERNAL_H
#define _LTTNG_UST_CONTEXT_PROVIDER_INTERNAL_H

#include <stddef.h>
#include <lttng/ust-events.h>

__attribute__((visibility("hidden")))
void lttng_ust_context_set_event_notifier_group_provider(const char *name,
		size_t (*get_size)(struct lttng_ust_ctx_field *field, size_t offset),
		void (*record)(struct lttng_ust_ctx_field *field,
			struct lttng_ust_lib_ring_buffer_ctx *ctx,
			struct lttng_channel *chan),
		void (*get_value)(struct lttng_ust_ctx_field *field,
			struct lttng_ust_ctx_value *value));

#endif /* _LTTNG_UST_CONTEXT_PROVIDER_INTERNAL_H */
