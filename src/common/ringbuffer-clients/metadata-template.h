/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2010-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng lib ring buffer client template.
 */

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include <urcu/tls-compat.h>

#include "common/bitfield.h"
#include "common/align.h"
#include "common/events.h"
#include "common/tracer.h"
#include "common/ringbuffer/frontend_types.h"

struct metadata_packet_header {
	uint32_t magic;			/* 0x75D11D57 */
	uint8_t  uuid[LTTNG_UST_UUID_LEN]; /* Unique Universal Identifier */
	uint32_t checksum;		/* 0 if unused */
	uint32_t content_size;		/* in bits */
	uint32_t packet_size;		/* in bits */
	uint8_t  compression_scheme;	/* 0 if unused */
	uint8_t  encryption_scheme;	/* 0 if unused */
	uint8_t  checksum_scheme;	/* 0 if unused */
	uint8_t  major;			/* CTF spec major version number */
	uint8_t  minor;			/* CTF spec minor version number */
	uint8_t  header_end[0];
};

struct metadata_record_header {
	uint8_t header_end[0];		/* End of header */
};

static const struct lttng_ust_ring_buffer_config client_config;

/* No nested use supported for metadata ring buffer. */
static DEFINE_URCU_TLS(struct lttng_ust_ring_buffer_ctx_private, private_ctx);

static inline uint64_t lib_ring_buffer_clock_read(
		struct lttng_ust_ring_buffer_channel *chan __attribute__((unused)))
{
	return 0;
}

static inline
size_t record_header_size(
		const struct lttng_ust_ring_buffer_config *config __attribute__((unused)),
		struct lttng_ust_ring_buffer_channel *chan __attribute__((unused)),
		size_t offset __attribute__((unused)),
		size_t *pre_header_padding __attribute__((unused)),
		struct lttng_ust_ring_buffer_ctx *ctx __attribute__((unused)),
		void *client_ctx __attribute__((unused)))
{
	return 0;
}

#include "common/ringbuffer/api.h"
#include "common/ringbuffer-clients/clients.h"

static uint64_t client_ring_buffer_clock_read(
		struct lttng_ust_ring_buffer_channel *chan __attribute__((unused)))
{
	return 0;
}

static
size_t client_record_header_size(
		const struct lttng_ust_ring_buffer_config *config __attribute__((unused)),
		struct lttng_ust_ring_buffer_channel *chan __attribute__((unused)),
		size_t offset __attribute__((unused)),
		size_t *pre_header_padding __attribute__((unused)),
		struct lttng_ust_ring_buffer_ctx *ctx __attribute__((unused)),
		void *client_ctx __attribute__((unused)))
{
	return 0;
}

/**
 * client_packet_header_size - called on buffer-switch to a new sub-buffer
 *
 * Return header size without padding after the structure. Don't use packed
 * structure because gcc generates inefficient code on some architectures
 * (powerpc, mips..)
 */
static size_t client_packet_header_size(void)
{
	return offsetof(struct metadata_packet_header, header_end);
}

static void client_buffer_begin(struct lttng_ust_ring_buffer *buf,
		uint64_t timestamp __attribute__((unused)),
		unsigned int subbuf_idx,
		struct lttng_ust_shm_handle *handle)
{
	struct lttng_ust_ring_buffer_channel *chan = shmp(handle, buf->backend.chan);
	struct metadata_packet_header *header =
		(struct metadata_packet_header *)
			lib_ring_buffer_offset_address(&buf->backend,
				subbuf_idx * chan->backend.subbuf_size,
				handle);
	struct lttng_ust_channel_buffer *lttng_chan = channel_get_private(chan);

	assert(header);
	if (!header)
		return;
	header->magic = TSDL_MAGIC_NUMBER;
	memcpy(header->uuid, lttng_chan->priv->uuid, sizeof(lttng_chan->priv->uuid));
	header->checksum = 0;		/* 0 if unused */
	header->content_size = 0xFFFFFFFF; /* in bits, for debugging */
	header->packet_size = 0xFFFFFFFF;  /* in bits, for debugging */
	header->compression_scheme = 0;	/* 0 if unused */
	header->encryption_scheme = 0;	/* 0 if unused */
	header->checksum_scheme = 0;	/* 0 if unused */
	header->major = CTF_SPEC_MAJOR;
	header->minor = CTF_SPEC_MINOR;
}

/*
 * offset is assumed to never be 0 here : never deliver a completely empty
 * subbuffer. data_size is between 1 and subbuf_size.
 */
static void client_buffer_end(struct lttng_ust_ring_buffer *buf,
		uint64_t timestamp  __attribute__((unused)),
		unsigned int subbuf_idx, unsigned long data_size,
		struct lttng_ust_shm_handle *handle,
		const struct lttng_ust_ring_buffer_ctx *ctx)
{
	struct lttng_ust_ring_buffer_channel *chan = shmp(handle, buf->backend.chan);
	struct metadata_packet_header *header =
		(struct metadata_packet_header *)
			lib_ring_buffer_offset_address(&buf->backend,
				subbuf_idx * chan->backend.subbuf_size,
				handle);
	unsigned long records_lost = 0;
	ssize_t page_size = LTTNG_UST_PAGE_SIZE;

	assert(header);
	if (!header)
		return;
	if (page_size < 0)
		return;
	header->content_size = data_size * CHAR_BIT;		/* in bits */
	header->packet_size = LTTNG_UST_ALIGN(data_size, page_size) * CHAR_BIT; /* in bits */
	/*
	 * We do not care about the records lost count, because the metadata
	 * channel waits and retry.
	 */
	(void) lib_ring_buffer_get_records_lost_full(&client_config, ctx);
	records_lost += lib_ring_buffer_get_records_lost_wrap(&client_config, ctx);
	records_lost += lib_ring_buffer_get_records_lost_big(&client_config, ctx);
	WARN_ON_ONCE(records_lost != 0);
}

static int client_buffer_create(
		struct lttng_ust_ring_buffer *buf __attribute__((unused)),
		void *priv __attribute__((unused)),
		int cpu __attribute__((unused)),
		const char *name __attribute__((unused)),
		struct lttng_ust_shm_handle *handle __attribute__((unused)))
{
	return 0;
}

static void client_buffer_finalize(
		struct lttng_ust_ring_buffer *buf __attribute__((unused)),
		void *priv __attribute__((unused)),
		int cpu __attribute__((unused)),
		struct lttng_ust_shm_handle *handle __attribute__((unused)))
{
}

static const
struct lttng_ust_client_lib_ring_buffer_client_cb client_cb = {
	.parent = {
		.ring_buffer_clock_read = client_ring_buffer_clock_read,
		.record_header_size = client_record_header_size,
		.subbuffer_header_size = client_packet_header_size,
		.buffer_begin = client_buffer_begin,
		.buffer_end = client_buffer_end,
		.buffer_create = client_buffer_create,
		.buffer_finalize = client_buffer_finalize,
	},
};

static const struct lttng_ust_ring_buffer_config client_config = {
	.cb.ring_buffer_clock_read = client_ring_buffer_clock_read,
	.cb.record_header_size = client_record_header_size,
	.cb.subbuffer_header_size = client_packet_header_size,
	.cb.buffer_begin = client_buffer_begin,
	.cb.buffer_end = client_buffer_end,
	.cb.buffer_create = client_buffer_create,
	.cb.buffer_finalize = client_buffer_finalize,

	.timestamp_bits = 0,
	.alloc = RING_BUFFER_ALLOC_PER_CHANNEL,
	.sync = RING_BUFFER_SYNC_PER_CHANNEL,
	.mode = RING_BUFFER_MODE_TEMPLATE,
	.backend = RING_BUFFER_PAGE,
	.output = RING_BUFFER_MMAP,
	.oops = RING_BUFFER_OOPS_CONSISTENCY,
	.ipi = RING_BUFFER_NO_IPI_BARRIER,
	.wakeup = RING_BUFFER_WAKEUP_BY_WRITER,
	.client_type = LTTNG_CLIENT_TYPE,

	 .cb_ptr = &client_cb.parent,
};

static
struct lttng_ust_channel_buffer *_channel_create(const char *name,
				void *buf_addr,
				size_t subbuf_size, size_t num_subbuf,
				unsigned int switch_timer_interval,
				unsigned int read_timer_interval,
				unsigned char *uuid,
				uint32_t chan_id,
				const int *stream_fds, int nr_stream_fds,
				int64_t blocking_timeout)
{
	struct lttng_ust_abi_channel_config chan_priv_init;
	struct lttng_ust_shm_handle *handle;
	struct lttng_ust_channel_buffer *lttng_chan_buf;

	lttng_chan_buf = lttng_ust_alloc_channel_buffer();
	if (!lttng_chan_buf)
		return NULL;
	memcpy(lttng_chan_buf->priv->uuid, uuid, LTTNG_UST_UUID_LEN);
	lttng_chan_buf->priv->id = chan_id;

	memset(&chan_priv_init, 0, sizeof(chan_priv_init));
	memcpy(chan_priv_init.uuid, uuid, LTTNG_UST_UUID_LEN);
	chan_priv_init.id = chan_id;

	handle = channel_create(&client_config, name,
			__alignof__(struct lttng_ust_channel_buffer),
			sizeof(struct lttng_ust_channel_buffer),
			&chan_priv_init,
			lttng_chan_buf, buf_addr, subbuf_size, num_subbuf,
			switch_timer_interval, read_timer_interval,
			stream_fds, nr_stream_fds, blocking_timeout);
	if (!handle)
		goto error;
	lttng_chan_buf->priv->rb_chan = shmp(handle, handle->chan);
	return lttng_chan_buf;

error:
	lttng_ust_free_channel_common(lttng_chan_buf->parent);
	return NULL;
}

static
void lttng_channel_destroy(struct lttng_ust_channel_buffer *lttng_chan_buf)
{
	channel_destroy(lttng_chan_buf->priv->rb_chan, lttng_chan_buf->priv->rb_chan->handle, 1);
	lttng_ust_free_channel_common(lttng_chan_buf->parent);
}

static
int lttng_event_reserve(struct lttng_ust_ring_buffer_ctx *ctx)
{
	int ret;

	memset(&URCU_TLS(private_ctx), 0, sizeof(struct lttng_ust_ring_buffer_ctx_private));
	URCU_TLS(private_ctx).pub = ctx;
	URCU_TLS(private_ctx).chan = ctx->client_priv;
	ctx->priv = &URCU_TLS(private_ctx);
	ret = lib_ring_buffer_reserve(&client_config, ctx, NULL);
	if (ret)
		return ret;
	if (lib_ring_buffer_backend_get_pages(&client_config, ctx,
			&ctx->priv->backend_pages))
		return -EPERM;
	return 0;
}

static
void lttng_event_commit(struct lttng_ust_ring_buffer_ctx *ctx)
{
	lib_ring_buffer_commit(&client_config, ctx);
}

static
void lttng_event_write(struct lttng_ust_ring_buffer_ctx *ctx,
		const void *src, size_t len, size_t alignment)
{
	lttng_ust_ring_buffer_align_ctx(ctx, alignment);
	lib_ring_buffer_write(&client_config, ctx, src, len);
}

static
size_t lttng_packet_avail_size(struct lttng_ust_channel_buffer *chan)
{
	struct lttng_ust_ring_buffer_channel *rb_chan = chan->priv->rb_chan;
	unsigned long o_begin;
	struct lttng_ust_ring_buffer *buf;

	buf = shmp(rb_chan->handle, rb_chan->backend.buf[0].shmp);	/* Only for global buffer ! */
	o_begin = v_read(&client_config, &buf->offset);
	if (subbuf_offset(o_begin, rb_chan) != 0) {
		return rb_chan->backend.subbuf_size - subbuf_offset(o_begin, rb_chan);
	} else {
		return rb_chan->backend.subbuf_size - subbuf_offset(o_begin, rb_chan)
			- sizeof(struct metadata_packet_header);
	}
}

static
int lttng_is_finalized(struct lttng_ust_channel_buffer *chan)
{
	struct lttng_ust_ring_buffer_channel *rb_chan = chan->priv->rb_chan;

	return lib_ring_buffer_channel_is_finalized(rb_chan);
}

static
int lttng_is_disabled(struct lttng_ust_channel_buffer *chan)
{
	struct lttng_ust_ring_buffer_channel *rb_chan = chan->priv->rb_chan;

	return lib_ring_buffer_channel_is_disabled(rb_chan);
}

static
int lttng_flush_buffer(struct lttng_ust_channel_buffer *chan)
{
	struct lttng_ust_ring_buffer_channel *rb_chan = chan->priv->rb_chan;
	struct lttng_ust_ring_buffer *buf;
	int shm_fd, wait_fd, wakeup_fd;
	uint64_t memory_map_size;
	void *memory_map_addr;

	buf = channel_get_ring_buffer(&client_config, rb_chan,
			0, rb_chan->handle, &shm_fd, &wait_fd, &wakeup_fd,
			&memory_map_size, &memory_map_addr);
	lib_ring_buffer_switch(&client_config, buf,
			SWITCH_ACTIVE, rb_chan->handle);
	return 0;
}

static struct lttng_transport lttng_relay_transport = {
	.name = "relay-" RING_BUFFER_MODE_TEMPLATE_STRING "-mmap",
	.ops = {
		.struct_size = sizeof(struct lttng_ust_channel_buffer_ops),

		.priv = LTTNG_UST_COMPOUND_LITERAL(struct lttng_ust_channel_buffer_ops_private, {
			.pub = &lttng_relay_transport.ops,
			.channel_create = _channel_create,
			.channel_destroy = lttng_channel_destroy,
			.packet_avail_size = lttng_packet_avail_size,
			.is_finalized = lttng_is_finalized,
			.is_disabled = lttng_is_disabled,
			.flush_buffer = lttng_flush_buffer,
		}),
		.event_reserve = lttng_event_reserve,
		.event_commit = lttng_event_commit,
		.event_write = lttng_event_write,
	},
	.client_config = &client_config,
};

void RING_BUFFER_MODE_TEMPLATE_INIT(void)
{
	DBG("LTT : ltt ring buffer client \"%s\" init\n",
		"relay-" RING_BUFFER_MODE_TEMPLATE_STRING "-mmap");
	lttng_transport_register(&lttng_relay_transport);
}

void RING_BUFFER_MODE_TEMPLATE_EXIT(void)
{
	DBG("LTT : ltt ring buffer client \"%s\" exit\n",
		"relay-" RING_BUFFER_MODE_TEMPLATE_STRING "-mmap");
	lttng_transport_unregister(&lttng_relay_transport);
}
