/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#define _LGPL_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include <lttng/ust-ringbuffer-context.h>

#include "common/logging.h"
#include "common/tracer.h"
#include "common/jhash.h"


/*
 * Each library using the transports will have its local lists.
 */
static CDS_LIST_HEAD(lttng_transport_list);
static CDS_LIST_HEAD(lttng_counter_transport_list);

struct lttng_transport *lttng_ust_transport_find(const char *name)
{
	struct lttng_transport *transport;

	cds_list_for_each_entry(transport, &lttng_transport_list, node) {
		if (!strcmp(transport->name, name))
			return transport;
	}
	return NULL;
}

struct lttng_counter_transport *lttng_counter_transport_find(const char *name)
{
	struct lttng_counter_transport *transport;

	cds_list_for_each_entry(transport, &lttng_counter_transport_list, node) {
		if (!strcmp(transport->name, name))
			return transport;
	}
	return NULL;
}

/**
 * lttng_transport_register - LTT transport registration
 * @transport: transport structure
 *
 * Registers a transport which can be used as output to extract the data out of
 * LTTng. Called with ust_lock held.
 */
void lttng_transport_register(struct lttng_transport *transport)
{
	cds_list_add_tail(&transport->node, &lttng_transport_list);
}

/**
 * lttng_transport_unregister - LTT transport unregistration
 * @transport: transport structure
 * Called with ust_lock held.
 */
void lttng_transport_unregister(struct lttng_transport *transport)
{
	cds_list_del(&transport->node);
}

/**
 * lttng_counter_transport_register - LTTng counter transport registration
 * @transport: transport structure
 *
 * Registers a counter transport which can be used as output to extract
 * the data out of LTTng. Called with ust_lock held.
 */
void lttng_counter_transport_register(struct lttng_counter_transport *transport)
{
	cds_list_add_tail(&transport->node, &lttng_counter_transport_list);
}

/**
 * lttng_counter_transport_unregister - LTTng counter transport unregistration
 * @transport: transport structure
 * Called with ust_lock held.
 */
void lttng_counter_transport_unregister(struct lttng_counter_transport *transport)
{
	cds_list_del(&transport->node);
}

size_t lttng_ust_dummy_get_size(void *priv __attribute__((unused)),
		struct lttng_ust_probe_ctx *probe_ctx __attribute__((unused)),
		size_t offset)
{
	size_t size = 0;

	size += lttng_ust_ring_buffer_align(offset, lttng_ust_rb_alignof(char));
	size += sizeof(char);		/* tag */
	return size;
}

void lttng_ust_dummy_record(void *priv __attribute__((unused)),
		struct lttng_ust_probe_ctx *probe_ctx __attribute__((unused)),
		struct lttng_ust_ring_buffer_ctx *ctx,
		struct lttng_ust_channel_buffer *chan)
{
	char sel_char = (char) LTTNG_UST_DYNAMIC_TYPE_NONE;

	chan->ops->event_write(ctx, &sel_char, sizeof(sel_char), lttng_ust_rb_alignof(sel_char));
}

void lttng_ust_dummy_get_value(void *priv __attribute__((unused)),
		struct lttng_ust_probe_ctx *probe_ctx __attribute__((unused)),
		struct lttng_ust_ctx_value *value)
{
	value->sel = LTTNG_UST_DYNAMIC_TYPE_NONE;
}

int lttng_context_is_app(const char *name)
{
	if (strncmp(name, "$app.", strlen("$app.")) != 0) {
		return 0;
	}
	return 1;
}

struct lttng_ust_channel_buffer *lttng_ust_alloc_channel_buffer(void)
{
	struct lttng_ust_channel_buffer *lttng_chan_buf;
	struct lttng_ust_channel_common *lttng_chan_common;
	struct lttng_ust_channel_buffer_private *lttng_chan_buf_priv;

	lttng_chan_buf = zmalloc(sizeof(struct lttng_ust_channel_buffer));
	if (!lttng_chan_buf)
		goto lttng_chan_buf_error;
	lttng_chan_buf->struct_size = sizeof(struct lttng_ust_channel_buffer);
	lttng_chan_common = zmalloc(sizeof(struct lttng_ust_channel_common));
	if (!lttng_chan_common)
		goto lttng_chan_common_error;
	lttng_chan_common->struct_size = sizeof(struct lttng_ust_channel_common);
	lttng_chan_buf_priv = zmalloc(sizeof(struct lttng_ust_channel_buffer_private));
	if (!lttng_chan_buf_priv)
		goto lttng_chan_buf_priv_error;
	lttng_chan_buf->parent = lttng_chan_common;
	lttng_chan_common->type = LTTNG_UST_CHANNEL_TYPE_BUFFER;
	lttng_chan_common->child = lttng_chan_buf;
	lttng_chan_buf->priv = lttng_chan_buf_priv;
	lttng_chan_common->priv = &lttng_chan_buf_priv->parent;
	lttng_chan_buf_priv->pub = lttng_chan_buf;
	lttng_chan_buf_priv->parent.pub = lttng_chan_common;

	return lttng_chan_buf;

lttng_chan_buf_priv_error:
	free(lttng_chan_common);
lttng_chan_common_error:
	free(lttng_chan_buf);
lttng_chan_buf_error:
	return NULL;
}

struct lttng_ust_channel_counter *lttng_ust_alloc_channel_counter(void)
{
	struct lttng_ust_channel_counter *lttng_chan_counter;
	struct lttng_ust_channel_common *lttng_chan_common;
	struct lttng_ust_channel_counter_private *lttng_chan_counter_priv;

	lttng_chan_counter = zmalloc(sizeof(struct lttng_ust_channel_counter));
	if (!lttng_chan_counter)
		goto lttng_chan_counter_error;
	lttng_chan_counter->struct_size = sizeof(struct lttng_ust_channel_counter);
	lttng_chan_common = zmalloc(sizeof(struct lttng_ust_channel_common));
	if (!lttng_chan_common)
		goto lttng_chan_common_error;
	lttng_chan_common->struct_size = sizeof(struct lttng_ust_channel_common);
	lttng_chan_counter_priv = zmalloc(sizeof(struct lttng_ust_channel_counter_private));
	if (!lttng_chan_counter_priv)
		goto lttng_chan_counter_priv_error;
	lttng_chan_counter->parent = lttng_chan_common;
	lttng_chan_common->type = LTTNG_UST_CHANNEL_TYPE_COUNTER;
	lttng_chan_common->child = lttng_chan_counter;
	lttng_chan_counter->priv = lttng_chan_counter_priv;
	lttng_chan_common->priv = &lttng_chan_counter_priv->parent;
	lttng_chan_counter_priv->pub = lttng_chan_counter;
	lttng_chan_counter_priv->parent.pub = lttng_chan_common;

	return lttng_chan_counter;

lttng_chan_counter_priv_error:
	free(lttng_chan_common);
lttng_chan_common_error:
	free(lttng_chan_counter);
lttng_chan_counter_error:
	return NULL;
}

void lttng_ust_free_channel_common(struct lttng_ust_channel_common *chan)
{
	switch (chan->type) {
	case LTTNG_UST_CHANNEL_TYPE_BUFFER:
	{
		struct lttng_ust_channel_buffer *chan_buf;

		chan_buf = (struct lttng_ust_channel_buffer *)chan->child;
		free(chan_buf->parent);
		free(chan_buf->priv);
		free(chan_buf);
		break;
	}
	case LTTNG_UST_CHANNEL_TYPE_COUNTER:
	{
		struct lttng_ust_channel_counter *chan_counter;

		chan_counter = (struct lttng_ust_channel_counter *)chan->child;
		free(chan_counter->parent);
		free(chan_counter->priv);
		free(chan_counter);
		break;
	}
	default:
		abort();
	}
}

