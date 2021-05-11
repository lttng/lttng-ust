/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2019 Francis Deslauriers <francis.deslauriers@efficios.com>
 */

#ifndef _LTTNG_UST_CONTEXT_PROVIDER_INTERNAL_H
#define _LTTNG_UST_CONTEXT_PROVIDER_INTERNAL_H

#include <stddef.h>
#include <lttng/ust-events.h>

void lttng_ust_context_set_event_notifier_group_provider(const char *name,
		size_t (*get_size)(void *priv, struct lttng_ust_probe_ctx *probe_ctx,
			size_t offset),
		void (*record)(void *priv, struct lttng_ust_probe_ctx *probe_ctx,
			struct lttng_ust_ring_buffer_ctx *ctx,
			struct lttng_ust_channel_buffer *chan),
		void (*get_value)(void *priv, struct lttng_ust_probe_ctx *probe_ctx,
			struct lttng_ust_ctx_value *value))
	__attribute__((visibility("hidden")));

#endif /* _LTTNG_UST_CONTEXT_PROVIDER_INTERNAL_H */
