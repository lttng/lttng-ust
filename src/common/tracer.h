/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2005-2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This contains the definitions for the Linux Trace Toolkit tracer.
 *
 * Ported to userspace by Pierre-Marc Fournier.
 */

#ifndef _UST_COMMON_TRACER_H
#define _UST_COMMON_TRACER_H

#include <stddef.h>

#include "common/events.h"

/* Tracer properties */
#define CTF_MAGIC_NUMBER		0xC1FC1FC1
#define TSDL_MAGIC_NUMBER		0x75D11D57

/* CTF specification version followed */
#define CTF_SPEC_MAJOR			1
#define CTF_SPEC_MINOR			8

#define LTTNG_RFLAG_EXTENDED		RING_BUFFER_RFLAG_END
#define LTTNG_RFLAG_END			(LTTNG_RFLAG_EXTENDED << 1)

#define LTTNG_TRACE_PRINTF_BUFSIZE	512

/*
 * LTTng client type enumeration. Used by the consumer to map the
 * callbacks from its own address space.
 */
enum lttng_client_types {
	LTTNG_CLIENT_METADATA = 0,
	LTTNG_CLIENT_DISCARD = 1,
	LTTNG_CLIENT_OVERWRITE = 2,
	LTTNG_CLIENT_DISCARD_RT = 3,
	LTTNG_CLIENT_OVERWRITE_RT = 4,
	LTTNG_CLIENT_DISCARD_PER_CHANNEL = 5,
	LTTNG_CLIENT_OVERWRITE_PER_CHANNEL = 6,
	LTTNG_CLIENT_DISCARD_PER_CHANNEL_RT = 7,
	LTTNG_CLIENT_OVERWRITE_PER_CHANNEL_RT = 8,
	LTTNG_NR_CLIENT_TYPES,
};

struct lttng_transport *lttng_ust_transport_find(const char *name)
	__attribute__((visibility("hidden")));

void lttng_transport_register(struct lttng_transport *transport)
	__attribute__((visibility("hidden")));

void lttng_transport_unregister(struct lttng_transport *transport)
	__attribute__((visibility("hidden")));


struct lttng_counter_transport *lttng_counter_transport_find(const char *name)
	__attribute__((visibility("hidden")));

void lttng_counter_transport_register(struct lttng_counter_transport *transport)
	__attribute__((visibility("hidden")));

void lttng_counter_transport_unregister(struct lttng_counter_transport *transport)
	__attribute__((visibility("hidden")));


size_t lttng_ust_dummy_get_size(void *priv, struct lttng_ust_probe_ctx *probe_ctx,
		size_t offset)
	__attribute__((visibility("hidden")));

void lttng_ust_dummy_record(void *priv, struct lttng_ust_probe_ctx *probe_ctx,
		struct lttng_ust_ring_buffer_ctx *ctx,
		struct lttng_ust_channel_buffer *chan)
	__attribute__((visibility("hidden")));

void lttng_ust_dummy_get_value(void *priv, struct lttng_ust_probe_ctx *probe_ctx,
		struct lttng_ust_ctx_value *value)
	__attribute__((visibility("hidden")));

int lttng_context_is_app(const char *name)
	__attribute__((visibility("hidden")));

struct lttng_ust_channel_buffer *lttng_ust_alloc_channel_buffer(void)
	__attribute__((visibility("hidden")));

struct lttng_ust_channel_counter *lttng_ust_alloc_channel_counter(void)
	__attribute__((visibility("hidden")));

void lttng_ust_free_channel_common(struct lttng_ust_channel_common *chan)
	__attribute__((visibility("hidden")));

#endif /* _UST_COMMON_TRACER_H */
