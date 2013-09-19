/*
 * lttng-ring-buffer-client.h
 *
 * LTTng lib ring buffer client template.
 *
 * Copyright (C) 2010-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <stdint.h>
#include <lttng/ust-events.h>
#include "lttng/bitfield.h"
#include "lttng-tracer.h"
#include "../libringbuffer/frontend_types.h"

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

static const struct lttng_ust_lib_ring_buffer_config client_config;

static inline uint64_t lib_ring_buffer_clock_read(struct channel *chan)
{
	return 0;
}

static inline
unsigned char record_header_size(const struct lttng_ust_lib_ring_buffer_config *config,
				 struct channel *chan, size_t offset,
				 size_t *pre_header_padding,
				 struct lttng_ust_lib_ring_buffer_ctx *ctx)
{
	return 0;
}

#include "../libringbuffer/api.h"
#include "lttng-rb-clients.h"

static uint64_t client_ring_buffer_clock_read(struct channel *chan)
{
	return 0;
}

static
size_t client_record_header_size(const struct lttng_ust_lib_ring_buffer_config *config,
				 struct channel *chan, size_t offset,
				 size_t *pre_header_padding,
				 struct lttng_ust_lib_ring_buffer_ctx *ctx)
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

static void client_buffer_begin(struct lttng_ust_lib_ring_buffer *buf, uint64_t tsc,
				unsigned int subbuf_idx,
				struct lttng_ust_shm_handle *handle)
{
	struct channel *chan = shmp(handle, buf->backend.chan);
	struct metadata_packet_header *header =
		(struct metadata_packet_header *)
			lib_ring_buffer_offset_address(&buf->backend,
				subbuf_idx * chan->backend.subbuf_size,
				handle);
	struct lttng_channel *lttng_chan = channel_get_private(chan);

	header->magic = TSDL_MAGIC_NUMBER;
	memcpy(header->uuid, lttng_chan->uuid, sizeof(lttng_chan->uuid));
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
static void client_buffer_end(struct lttng_ust_lib_ring_buffer *buf, uint64_t tsc,
			      unsigned int subbuf_idx, unsigned long data_size,
			      struct lttng_ust_shm_handle *handle)
{
	struct channel *chan = shmp(handle, buf->backend.chan);
	struct metadata_packet_header *header =
		(struct metadata_packet_header *)
			lib_ring_buffer_offset_address(&buf->backend,
				subbuf_idx * chan->backend.subbuf_size,
				handle);
	unsigned long records_lost = 0;

	header->content_size = data_size * CHAR_BIT;		/* in bits */
	header->packet_size = PAGE_ALIGN(data_size) * CHAR_BIT; /* in bits */
	/*
	 * We do not care about the records lost count, because the metadata
	 * channel waits and retry.
	 */
	(void) lib_ring_buffer_get_records_lost_full(&client_config, buf);
	records_lost += lib_ring_buffer_get_records_lost_wrap(&client_config, buf);
	records_lost += lib_ring_buffer_get_records_lost_big(&client_config, buf);
	WARN_ON_ONCE(records_lost != 0);
}

static int client_buffer_create(struct lttng_ust_lib_ring_buffer *buf, void *priv,
				int cpu, const char *name,
				struct lttng_ust_shm_handle *handle)
{
	return 0;
}

static void client_buffer_finalize(struct lttng_ust_lib_ring_buffer *buf,
				   void *priv, int cpu,
				   struct lttng_ust_shm_handle *handle)
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

static const struct lttng_ust_lib_ring_buffer_config client_config = {
	.cb.ring_buffer_clock_read = client_ring_buffer_clock_read,
	.cb.record_header_size = client_record_header_size,
	.cb.subbuffer_header_size = client_packet_header_size,
	.cb.buffer_begin = client_buffer_begin,
	.cb.buffer_end = client_buffer_end,
	.cb.buffer_create = client_buffer_create,
	.cb.buffer_finalize = client_buffer_finalize,

	.tsc_bits = 0,
	.alloc = RING_BUFFER_ALLOC_GLOBAL,
	.sync = RING_BUFFER_SYNC_GLOBAL,
	.mode = RING_BUFFER_MODE_TEMPLATE,
	.backend = RING_BUFFER_PAGE,
	.output = RING_BUFFER_MMAP,
	.oops = RING_BUFFER_OOPS_CONSISTENCY,
	.ipi = RING_BUFFER_NO_IPI_BARRIER,
	.wakeup = RING_BUFFER_WAKEUP_BY_WRITER,
	.client_type = LTTNG_CLIENT_TYPE,

	 .cb_ptr = &client_cb.parent,
};

const struct lttng_ust_client_lib_ring_buffer_client_cb *LTTNG_CLIENT_CALLBACKS = &client_cb;

static
struct lttng_channel *_channel_create(const char *name,
				void *buf_addr,
				size_t subbuf_size, size_t num_subbuf,
				unsigned int switch_timer_interval,
				unsigned int read_timer_interval,
				unsigned char *uuid,
				uint32_t chan_id)
{
	struct lttng_channel chan_priv_init;
	struct lttng_ust_shm_handle *handle;
	struct lttng_channel *lttng_chan;
	void *priv;

	memset(&chan_priv_init, 0, sizeof(chan_priv_init));
	memcpy(chan_priv_init.uuid, uuid, LTTNG_UST_UUID_LEN);
	chan_priv_init.id = chan_id;
	handle = channel_create(&client_config, name,
			&priv, __alignof__(struct lttng_channel),
			sizeof(struct lttng_channel),
			&chan_priv_init,
			buf_addr, subbuf_size, num_subbuf,
			switch_timer_interval, read_timer_interval);
	if (!handle)
		return NULL;
	lttng_chan = priv;
	lttng_chan->handle = handle;
	lttng_chan->chan = shmp(handle, handle->chan);
	return lttng_chan;
}

static
void lttng_channel_destroy(struct lttng_channel *chan)
{
	channel_destroy(chan->chan, chan->handle, 1);
}

static
int lttng_event_reserve(struct lttng_ust_lib_ring_buffer_ctx *ctx, uint32_t event_id)
{
	return lib_ring_buffer_reserve(&client_config, ctx);
}

static
void lttng_event_commit(struct lttng_ust_lib_ring_buffer_ctx *ctx)
{
	lib_ring_buffer_commit(&client_config, ctx);
}

static
void lttng_event_write(struct lttng_ust_lib_ring_buffer_ctx *ctx, const void *src,
		     size_t len)
{
	lib_ring_buffer_write(&client_config, ctx, src, len);
}

static
size_t lttng_packet_avail_size(struct channel *chan, struct lttng_ust_shm_handle *handle)
			     
{
	unsigned long o_begin;
	struct lttng_ust_lib_ring_buffer *buf;

	buf = shmp(handle, chan->backend.buf[0].shmp);	/* Only for global buffer ! */
	o_begin = v_read(&client_config, &buf->offset);
	if (subbuf_offset(o_begin, chan) != 0) {
		return chan->backend.subbuf_size - subbuf_offset(o_begin, chan);
	} else {
		return chan->backend.subbuf_size - subbuf_offset(o_begin, chan)
			- sizeof(struct metadata_packet_header);
	}
}

#if 0
static
wait_queue_head_t *lttng_get_reader_wait_queue(struct channel *chan)
{
	return &chan->read_wait;
}

static
wait_queue_head_t *lttng_get_hp_wait_queue(struct channel *chan)
{
	return &chan->hp_wait;
}
#endif //0

static
int lttng_is_finalized(struct channel *chan)
{
	return lib_ring_buffer_channel_is_finalized(chan);
}

static
int lttng_is_disabled(struct channel *chan)
{
	return lib_ring_buffer_channel_is_disabled(chan);
}

static
int lttng_flush_buffer(struct channel *chan, struct lttng_ust_shm_handle *handle)
{
	struct lttng_ust_lib_ring_buffer *buf;
	int shm_fd, wait_fd, wakeup_fd;
	uint64_t memory_map_size;

	buf = channel_get_ring_buffer(&client_config, chan,
			0, handle, &shm_fd, &wait_fd, &wakeup_fd,
			&memory_map_size);
	lib_ring_buffer_switch(&client_config, buf,
			SWITCH_ACTIVE, handle);
	return 0;
}

static struct lttng_transport lttng_relay_transport = {
	.name = "relay-" RING_BUFFER_MODE_TEMPLATE_STRING "-mmap",
	.ops = {
		.channel_create = _channel_create,
		.channel_destroy = lttng_channel_destroy,
		.event_reserve = lttng_event_reserve,
		.event_commit = lttng_event_commit,
		.event_write = lttng_event_write,
		.packet_avail_size = lttng_packet_avail_size,
		//.get_reader_wait_queue = lttng_get_reader_wait_queue,
		//.get_hp_wait_queue = lttng_get_hp_wait_queue,
		.is_finalized = lttng_is_finalized,
		.is_disabled = lttng_is_disabled,
		.flush_buffer = lttng_flush_buffer,
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
