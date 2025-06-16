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

#include <lttng/urcu/pointer.h>
#include <urcu/tls-compat.h>

#include "common/events.h"
#include "common/bitfield.h"
#include "common/align.h"
#include "common/clock.h"
#include "common/ringbuffer/frontend_types.h"

#define LTTNG_COMPACT_EVENT_BITS	5
#define LTTNG_COMPACT_TIMESTAMP_BITS	27

/*
 * Keep the natural field alignment for _each field_ within this structure if
 * you ever add/remove a field from this header. Packed attribute is not used
 * because gcc generates poor code on at least powerpc and mips. Don't ever
 * let gcc add padding between the structure elements.
 */

struct packet_header {
	/* Trace packet header */
	uint32_t magic;			/*
					 * Trace magic number.
					 * contains endianness information.
					 */
	uint8_t uuid[LTTNG_UST_UUID_LEN];
	uint32_t stream_id;
	uint64_t stream_instance_id;

	struct {
		/* Stream packet context */
		uint64_t timestamp_begin;	/* Cycle count at subbuffer start */
		uint64_t timestamp_end;		/* Cycle count at subbuffer end */
		uint64_t content_size;		/* Size of data in subbuffer */
		uint64_t packet_size;		/* Subbuffer size (include padding) */
		uint64_t packet_seq_num;	/* Packet sequence number */
		unsigned long events_discarded;	/*
						 * Events lost in this subbuffer since
						 * the beginning of the trace.
						 * (may overflow)
						 */
#ifdef RING_BUFFER_CLIENT_HAS_CPU_ID
		uint32_t cpu_id;		/* CPU id associated with stream */
#endif
		uint8_t header_end;		/* End of header */
	} ctx;
};

struct lttng_client_ctx {
	size_t packet_context_len;
	size_t event_context_len;
	struct lttng_ust_ctx *chan_ctx;
};

/*
 * Indexed by lib_ring_buffer_nesting_count().
 */
typedef struct lttng_ust_ring_buffer_ctx_private private_ctx_stack_t[LIB_RING_BUFFER_MAX_NESTING];
static DEFINE_URCU_TLS(private_ctx_stack_t, private_ctx_stack);

/*
 * Force a read (imply TLS allocation for dlopen) of TLS variables.
 */
void RING_BUFFER_MODE_TEMPLATE_ALLOC_TLS(void)
{
	__asm__ __volatile__ ("" : : "m" (URCU_TLS(private_ctx_stack)));
}

static inline uint64_t lib_ring_buffer_clock_read(
		struct lttng_ust_ring_buffer_channel *chan __attribute__((unused)))
{
	return trace_clock_read64();
}

static inline
size_t ctx_get_aligned_size(size_t offset, struct lttng_ust_ctx *ctx,
		size_t ctx_len)
{
	size_t orig_offset = offset;

	if (caa_likely(!ctx))
		return 0;
	offset += lttng_ust_ring_buffer_align(offset, ctx->largest_align);
	offset += ctx_len;
	return offset - orig_offset;
}

static inline
void ctx_get_struct_size(struct lttng_ust_ring_buffer_ctx *bufctx,
		struct lttng_ust_ctx *ctx, size_t *ctx_len)
{
	int i;
	size_t offset = 0;

	if (caa_likely(!ctx)) {
		*ctx_len = 0;
		return;
	}
	for (i = 0; i < ctx->nr_fields; i++)
		offset += ctx->fields[i].get_size(ctx->fields[i].priv, bufctx->probe_ctx, offset);
	*ctx_len = offset;
}

static inline
void ctx_record(struct lttng_ust_ring_buffer_ctx *bufctx,
		struct lttng_ust_channel_buffer *chan,
		struct lttng_ust_ctx *ctx)
{
	int i;

	if (caa_likely(!ctx))
		return;
	lttng_ust_ring_buffer_align_ctx(bufctx, ctx->largest_align);
	for (i = 0; i < ctx->nr_fields; i++)
		ctx->fields[i].record(ctx->fields[i].priv, bufctx->probe_ctx, bufctx, chan);
}

/*
 * record_header_size - Calculate the header size and padding necessary.
 * @config: ring buffer instance configuration
 * @chan: channel
 * @offset: offset in the write buffer
 * @pre_header_padding: padding to add before the header (output)
 * @ctx: reservation context
 *
 * Returns the event header size (including padding).
 *
 * The payload must itself determine its own alignment from the biggest type it
 * contains.
 */
static __inline__
size_t record_header_size(
		const struct lttng_ust_ring_buffer_config *config __attribute__((unused)),
		struct lttng_ust_ring_buffer_channel *chan,
		size_t offset,
		size_t *pre_header_padding,
		struct lttng_ust_ring_buffer_ctx *ctx,
		struct lttng_client_ctx *client_ctx)
{
	struct lttng_ust_channel_buffer *lttng_chan = channel_get_private(chan);
	size_t orig_offset = offset;
	size_t padding;

	switch (lttng_chan->priv->header_type) {
	case 1:	/* compact */
		padding = lttng_ust_ring_buffer_align(offset, lttng_ust_rb_alignof(uint32_t));
		offset += padding;
		if (!(ctx->priv->rflags & (RING_BUFFER_RFLAG_FULL_TIMESTAMP | LTTNG_RFLAG_EXTENDED))) {
			offset += sizeof(uint32_t);	/* id and timestamp */
		} else {
			/* Minimum space taken by LTTNG_COMPACT_EVENT_BITS id */
			offset += (LTTNG_COMPACT_EVENT_BITS + CHAR_BIT - 1) / CHAR_BIT;
			/* Align extended struct on largest member */
			offset += lttng_ust_ring_buffer_align(offset, lttng_ust_rb_alignof(uint64_t));
			offset += sizeof(uint32_t);	/* id */
			offset += lttng_ust_ring_buffer_align(offset, lttng_ust_rb_alignof(uint64_t));
			offset += sizeof(uint64_t);	/* timestamp */
		}
		break;
	case 2:	/* large */
		padding = lttng_ust_ring_buffer_align(offset, lttng_ust_rb_alignof(uint16_t));
		offset += padding;
		offset += sizeof(uint16_t);
		if (!(ctx->priv->rflags & (RING_BUFFER_RFLAG_FULL_TIMESTAMP | LTTNG_RFLAG_EXTENDED))) {
			offset += lttng_ust_ring_buffer_align(offset, lttng_ust_rb_alignof(uint32_t));
			offset += sizeof(uint32_t);	/* timestamp */
		} else {
			/* Align extended struct on largest member */
			offset += lttng_ust_ring_buffer_align(offset, lttng_ust_rb_alignof(uint64_t));
			offset += sizeof(uint32_t);	/* id */
			offset += lttng_ust_ring_buffer_align(offset, lttng_ust_rb_alignof(uint64_t));
			offset += sizeof(uint64_t);	/* timestamp */
		}
		break;
	default:
		padding = 0;
		WARN_ON_ONCE(1);
	}
	offset += ctx_get_aligned_size(offset, client_ctx->chan_ctx,
			client_ctx->packet_context_len);
	*pre_header_padding = padding;
	return offset - orig_offset;
}

#include "common/ringbuffer/api.h"
#include "common/ringbuffer-clients/clients.h"

static
void lttng_write_event_header_slow(const struct lttng_ust_ring_buffer_config *config,
				 struct lttng_ust_ring_buffer_ctx *ctx,
				 struct lttng_client_ctx *client_ctx,
				 uint32_t event_id);

/*
 * lttng_write_event_header
 *
 * Writes the event header to the offset (already aligned on 32-bits).
 *
 * @config: ring buffer instance configuration
 * @ctx: reservation context
 * @event_id: event ID
 */
static __inline__
void lttng_write_event_header(const struct lttng_ust_ring_buffer_config *config,
			    struct lttng_ust_ring_buffer_ctx *ctx,
			    struct lttng_client_ctx *client_ctx,
			    uint32_t event_id)
{
	struct lttng_ust_channel_buffer *lttng_chan = channel_get_private(ctx->priv->chan);

	if (caa_unlikely(ctx->priv->rflags))
		goto slow_path;

	switch (lttng_chan->priv->header_type) {
	case 1:	/* compact */
	{
		uint32_t id_time = 0;

		bt_bitfield_write(&id_time, uint32_t,
				0,
				LTTNG_COMPACT_EVENT_BITS,
				event_id);
		bt_bitfield_write(&id_time, uint32_t,
				LTTNG_COMPACT_EVENT_BITS,
				LTTNG_COMPACT_TIMESTAMP_BITS,
				ctx->priv->timestamp);
		lib_ring_buffer_write(config, ctx, &id_time, sizeof(id_time));
		break;
	}
	case 2:	/* large */
	{
		uint32_t timestamp = (uint32_t) ctx->priv->timestamp;
		uint16_t id = event_id;

		lib_ring_buffer_write(config, ctx, &id, sizeof(id));
		lttng_ust_ring_buffer_align_ctx(ctx, lttng_ust_rb_alignof(uint32_t));
		lib_ring_buffer_write(config, ctx, &timestamp, sizeof(timestamp));
		break;
	}
	default:
		WARN_ON_ONCE(1);
	}

	ctx_record(ctx, lttng_chan, client_ctx->chan_ctx);
	lttng_ust_ring_buffer_align_ctx(ctx, ctx->largest_align);

	return;

slow_path:
	lttng_write_event_header_slow(config, ctx, client_ctx, event_id);
}

static
void lttng_write_event_header_slow(const struct lttng_ust_ring_buffer_config *config,
				 struct lttng_ust_ring_buffer_ctx *ctx,
				 struct lttng_client_ctx *client_ctx,
				 uint32_t event_id)
{
	struct lttng_ust_ring_buffer_ctx_private *ctx_private = ctx->priv;
	struct lttng_ust_channel_buffer *lttng_chan = channel_get_private(ctx->priv->chan);

	switch (lttng_chan->priv->header_type) {
	case 1:	/* compact */
		if (!(ctx_private->rflags & (RING_BUFFER_RFLAG_FULL_TIMESTAMP | LTTNG_RFLAG_EXTENDED))) {
			uint32_t id_time = 0;

			bt_bitfield_write(&id_time, uint32_t,
					0,
					LTTNG_COMPACT_EVENT_BITS,
					event_id);
			bt_bitfield_write(&id_time, uint32_t,
					LTTNG_COMPACT_EVENT_BITS,
					LTTNG_COMPACT_TIMESTAMP_BITS,
					ctx_private->timestamp);
			lib_ring_buffer_write(config, ctx, &id_time, sizeof(id_time));
		} else {
			uint8_t id = 0;
			uint64_t timestamp = ctx_private->timestamp;

			bt_bitfield_write(&id, uint8_t,
					0,
					LTTNG_COMPACT_EVENT_BITS,
					31);
			lib_ring_buffer_write(config, ctx, &id, sizeof(id));
			/* Align extended struct on largest member */
			lttng_ust_ring_buffer_align_ctx(ctx, lttng_ust_rb_alignof(uint64_t));
			lib_ring_buffer_write(config, ctx, &event_id, sizeof(event_id));
			lttng_ust_ring_buffer_align_ctx(ctx, lttng_ust_rb_alignof(uint64_t));
			lib_ring_buffer_write(config, ctx, &timestamp, sizeof(timestamp));
		}
		break;
	case 2:	/* large */
	{
		if (!(ctx_private->rflags & (RING_BUFFER_RFLAG_FULL_TIMESTAMP | LTTNG_RFLAG_EXTENDED))) {
			uint32_t timestamp = (uint32_t) ctx_private->timestamp;
			uint16_t id = event_id;

			lib_ring_buffer_write(config, ctx, &id, sizeof(id));
			lttng_ust_ring_buffer_align_ctx(ctx, lttng_ust_rb_alignof(uint32_t));
			lib_ring_buffer_write(config, ctx, &timestamp, sizeof(timestamp));
		} else {
			uint16_t id = 65535;
			uint64_t timestamp = ctx_private->timestamp;

			lib_ring_buffer_write(config, ctx, &id, sizeof(id));
			/* Align extended struct on largest member */
			lttng_ust_ring_buffer_align_ctx(ctx, lttng_ust_rb_alignof(uint64_t));
			lib_ring_buffer_write(config, ctx, &event_id, sizeof(event_id));
			lttng_ust_ring_buffer_align_ctx(ctx, lttng_ust_rb_alignof(uint64_t));
			lib_ring_buffer_write(config, ctx, &timestamp, sizeof(timestamp));
		}
		break;
	}
	default:
		WARN_ON_ONCE(1);
	}
	ctx_record(ctx, lttng_chan, client_ctx->chan_ctx);
	lttng_ust_ring_buffer_align_ctx(ctx, ctx->largest_align);
}

static const struct lttng_ust_ring_buffer_config client_config;

static uint64_t client_ring_buffer_clock_read(struct lttng_ust_ring_buffer_channel *chan)
{
	return lib_ring_buffer_clock_read(chan);
}

static
size_t client_record_header_size(const struct lttng_ust_ring_buffer_config *config,
				 struct lttng_ust_ring_buffer_channel *chan,
				 size_t offset,
				 size_t *pre_header_padding,
				 struct lttng_ust_ring_buffer_ctx *ctx,
				 void *client_ctx)
{
	return record_header_size(config, chan, offset,
				  pre_header_padding, ctx, client_ctx);
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
	return offsetof(struct packet_header, ctx.header_end);
}

static void client_buffer_begin(struct lttng_ust_ring_buffer *buf, uint64_t timestamp,
				unsigned int subbuf_idx,
				struct lttng_ust_shm_handle *handle)
{
	struct lttng_ust_ring_buffer_channel *chan = shmp(handle, buf->backend.chan);
	struct packet_header *header =
		(struct packet_header *)
			lib_ring_buffer_offset_address(&buf->backend,
				subbuf_idx * chan->backend.subbuf_size,
				handle);
	struct lttng_ust_channel_buffer *lttng_chan = channel_get_private(chan);
	uint64_t cnt = shmp_index(handle, buf->backend.buf_cnt, subbuf_idx)->seq_cnt;

	assert(header);
	if (!header)
		return;
	header->magic = CTF_MAGIC_NUMBER;
	memcpy(header->uuid, lttng_chan->priv->uuid, sizeof(lttng_chan->priv->uuid));
	header->stream_id = lttng_chan->priv->id;
#ifdef RING_BUFFER_CLIENT_HAS_CPU_ID
	header->stream_instance_id = buf->backend.cpu;
#else
	header->stream_instance_id = 0;
#endif
	header->ctx.timestamp_begin = timestamp;
	header->ctx.timestamp_end = 0;
	header->ctx.content_size = ~0ULL; /* for debugging */
	header->ctx.packet_size = ~0ULL;
	header->ctx.packet_seq_num = chan->backend.num_subbuf * cnt + subbuf_idx;
	header->ctx.events_discarded = 0;
#ifdef RING_BUFFER_CLIENT_HAS_CPU_ID
	header->ctx.cpu_id = buf->backend.cpu;
#endif
}

/*
 * offset is assumed to never be 0 here : never deliver a completely empty
 * subbuffer. data_size is between 1 and subbuf_size.
 */
static void client_buffer_end(struct lttng_ust_ring_buffer *buf, uint64_t timestamp,
			      unsigned int subbuf_idx, unsigned long data_size,
			      struct lttng_ust_shm_handle *handle,
			      const struct lttng_ust_ring_buffer_ctx *ctx __attribute__((unused)))
{
	struct lttng_ust_ring_buffer_channel *chan = shmp(handle, buf->backend.chan);
	struct commit_counters_cold *cc_cold = shmp_index(handle, buf->commit_cold, subbuf_idx);
	struct packet_header *header =
		(struct packet_header *)
			lib_ring_buffer_offset_address(&buf->backend,
				subbuf_idx * chan->backend.subbuf_size,
				handle);
	ssize_t page_size = LTTNG_UST_PAGE_SIZE;

	assert(header);
	assert(cc_cold);
	if (!header)
		return;
	if (page_size < 0)
		return;
	if (!cc_cold)
		return;

	header->ctx.timestamp_end = timestamp;
	header->ctx.content_size =
		(uint64_t) data_size * CHAR_BIT;		/* in bits */
	header->ctx.packet_size =
		(uint64_t) LTTNG_UST_ALIGN(data_size, page_size) * CHAR_BIT;	/* in bits */
	header->ctx.events_discarded = cc_cold->end_events_discarded;
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

static void client_content_size_field(
		const struct lttng_ust_ring_buffer_config *config __attribute__((unused)),
		size_t *offset, size_t *length)
{
	*offset = offsetof(struct packet_header, ctx.content_size);
	*length = sizeof(((struct packet_header *) NULL)->ctx.content_size);
}

static void client_packet_size_field(
		const struct lttng_ust_ring_buffer_config *config __attribute__((unused)),
		size_t *offset, size_t *length)
{
	*offset = offsetof(struct packet_header, ctx.packet_size);
	*length = sizeof(((struct packet_header *) NULL)->ctx.packet_size);
}

static struct packet_header *client_packet_header(struct lttng_ust_ring_buffer *buf,
		struct lttng_ust_shm_handle *handle)
{
	return lib_ring_buffer_read_offset_address(&buf->backend, 0, handle);
}

static int client_timestamp_begin(struct lttng_ust_ring_buffer *buf,
		struct lttng_ust_ring_buffer_channel *chan,
		uint64_t *timestamp_begin)
{
	struct lttng_ust_shm_handle *handle = chan->handle;
	struct packet_header *header;

	header = client_packet_header(buf, handle);
	if (!header)
		return -1;
	*timestamp_begin = header->ctx.timestamp_begin;
	return 0;
}

static int client_timestamp_end(struct lttng_ust_ring_buffer *buf,
		struct lttng_ust_ring_buffer_channel *chan,
		uint64_t *timestamp_end)
{
	struct lttng_ust_shm_handle *handle = chan->handle;
	struct packet_header *header;

	header = client_packet_header(buf, handle);
	if (!header)
		return -1;
	*timestamp_end = header->ctx.timestamp_end;
	return 0;
}

static int client_events_discarded(struct lttng_ust_ring_buffer *buf,
		struct lttng_ust_ring_buffer_channel *chan,
		uint64_t *events_discarded)
{
	struct lttng_ust_shm_handle *handle = chan->handle;
	struct packet_header *header;

	header = client_packet_header(buf, handle);
	if (!header)
		return -1;
	*events_discarded = header->ctx.events_discarded;
	return 0;
}

static int client_content_size(struct lttng_ust_ring_buffer *buf,
		struct lttng_ust_ring_buffer_channel *chan,
		uint64_t *content_size)
{
	struct lttng_ust_shm_handle *handle = chan->handle;
	struct packet_header *header;

	header = client_packet_header(buf, handle);
	if (!header)
		return -1;
	*content_size = header->ctx.content_size;
	return 0;
}

static int client_packet_size(struct lttng_ust_ring_buffer *buf,
		struct lttng_ust_ring_buffer_channel *chan,
		uint64_t *packet_size)
{
	struct lttng_ust_shm_handle *handle = chan->handle;
	struct packet_header *header;

	header = client_packet_header(buf, handle);
	if (!header)
		return -1;
	*packet_size = header->ctx.packet_size;
	return 0;
}

static int client_stream_id(struct lttng_ust_ring_buffer *buf __attribute__((unused)),
		struct lttng_ust_ring_buffer_channel *chan,
		uint64_t *stream_id)
{
	struct lttng_ust_channel_buffer *lttng_chan = channel_get_private(chan);

	*stream_id = lttng_chan->priv->id;

	return 0;
}

/*
 * Samples the events discarded counters of the ring buffer.
 */
static int client_current_events_discarded(
		struct lttng_ust_ring_buffer *buf,
		struct lttng_ust_ring_buffer_channel *chan,
		uint64_t *events_discarded)
{
	uint64_t e = 0;

	if (!events_discarded) {
		return -1;
	}

	e += v_read(&chan->backend.config, &buf->records_lost_full);
	e += v_read(&chan->backend.config, &buf->records_lost_wrap);
	e += v_read(&chan->backend.config, &buf->records_lost_big);
	*events_discarded = e;
	return 0;
}

static int client_current_timestamp(
		struct lttng_ust_ring_buffer *buf  __attribute__((unused)),
		struct lttng_ust_ring_buffer_channel *chan,
		uint64_t *ts)
{
	*ts = client_ring_buffer_clock_read(chan);

	return 0;
}

static int client_sequence_number(struct lttng_ust_ring_buffer *buf,
		struct lttng_ust_ring_buffer_channel *chan,
		uint64_t *seq)
{
	struct lttng_ust_shm_handle *handle = chan->handle;
	struct packet_header *header;

	header = client_packet_header(buf, handle);
	if (!header)
		return -1;
	*seq = header->ctx.packet_seq_num;
	return 0;
}

static int client_instance_id(struct lttng_ust_ring_buffer *buf,
		struct lttng_ust_ring_buffer_channel *chan __attribute__((unused)),
		uint64_t *id)
{
#ifdef RING_BUFFER_CLIENT_HAS_CPU_ID
	*id = buf->backend.cpu;
#else
	(void) buf;
	*id = 0;
#endif
	return 0;
}

static int client_packet_initialize(struct lttng_ust_ring_buffer *buf,
		struct lttng_ust_ring_buffer_channel *chan,
		void *packet,
		uint64_t timestamp_begin, uint64_t timestamp_end,
		uint64_t sequence_number, uint64_t events_discarded,
		uint64_t *packet_length, uint64_t *packet_length_padded)
{
	struct packet_header *packet_header = (struct packet_header *)packet;
	struct lttng_ust_channel_buffer *lttng_chan_buf;
	ssize_t page_size = LTTNG_UST_PAGE_SIZE;
	size_t size;

	assert(packet);
	assert(packet_length);
	assert(packet_length_padded);
	if (!buf || !chan)
		return -EINVAL;
	if (page_size < 0)
		return -EINVAL;

	size = LTTNG_UST_ALIGN(client_packet_header_size(), page_size);
	memset(packet, 0, size);
	lttng_chan_buf = channel_get_private(chan);
	/*
	 * See client_buffer_begin().
	 */
	packet_header->magic = CTF_MAGIC_NUMBER;
	memcpy(packet_header->uuid, lttng_chan_buf->priv->uuid, sizeof(lttng_chan_buf->priv->uuid));
	packet_header->stream_id = lttng_chan_buf->priv->id;
	packet_header->stream_instance_id = buf->backend.cpu;
	packet_header->ctx.timestamp_begin = timestamp_begin;
	packet_header->ctx.timestamp_end = timestamp_end;
	packet_header->ctx.content_size = client_packet_header_size() * CHAR_BIT;
	packet_header->ctx.packet_size = size * CHAR_BIT;
	packet_header->ctx.events_discarded = (unsigned long) events_discarded;
#ifdef RING_BUFFER_CLIENT_HAS_CPU_ID
	packet_header->ctx.cpu_id = buf->backend.cpu;
#endif
	packet_header->ctx.packet_seq_num = sequence_number;
	*packet_length = client_packet_header_size();
	*packet_length_padded = size;
	return 0;
}

/*
 * The caller must free the pointer stored in packet when done.
 */
static int client_packet_create(void **packet, uint64_t *packet_length)
{
	ssize_t page_size = LTTNG_UST_PAGE_SIZE;
	void *new_packet = NULL;
	size_t size;

	assert(packet);
	assert(packet_length);

	if (page_size < 0)
		return -EINVAL;
	size = LTTNG_UST_ALIGN(client_packet_header_size(), page_size);
	new_packet = zmalloc(size);
	if (!new_packet) {
		*packet = NULL;
		*packet_length = 0;
		return -ENOMEM;
	}

	*packet = new_packet;
	*packet_length = size;
	return 0;
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
		.content_size_field = client_content_size_field,
		.packet_size_field = client_packet_size_field,
	},
	.timestamp_begin = client_timestamp_begin,
	.timestamp_end = client_timestamp_end,
	.events_discarded = client_events_discarded,
	.content_size = client_content_size,
	.packet_size = client_packet_size,
	.stream_id = client_stream_id,
	.current_events_discarded = client_current_events_discarded,
	.current_timestamp = client_current_timestamp,
	.sequence_number = client_sequence_number,
	.instance_id = client_instance_id,
	.packet_create = client_packet_create,
	.packet_initialize = client_packet_initialize,
};

static const struct lttng_ust_ring_buffer_config client_config = {
	.cb.ring_buffer_clock_read = client_ring_buffer_clock_read,
	.cb.record_header_size = client_record_header_size,
	.cb.subbuffer_header_size = client_packet_header_size,
	.cb.buffer_begin = client_buffer_begin,
	.cb.buffer_end = client_buffer_end,
	.cb.buffer_create = client_buffer_create,
	.cb.buffer_finalize = client_buffer_finalize,
	.cb.content_size_field = client_content_size_field,
	.cb.packet_size_field = client_packet_size_field,
	.timestamp_bits = LTTNG_COMPACT_TIMESTAMP_BITS,
	.alloc = RING_BUFFER_ALLOC_TEMPLATE,
	.sync = RING_BUFFER_SYNC_PER_CHANNEL,
	.mode = RING_BUFFER_MODE_TEMPLATE,
	.backend = RING_BUFFER_PAGE,
	.output = RING_BUFFER_MMAP,
	.oops = RING_BUFFER_OOPS_CONSISTENCY,
	.ipi = RING_BUFFER_NO_IPI_BARRIER,
	.wakeup = LTTNG_CLIENT_WAKEUP,
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
			__alignof__(struct lttng_ust_abi_channel_config),
			sizeof(struct lttng_ust_abi_channel_config),
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
	struct lttng_ust_event_recorder *event_recorder = ctx->client_priv;
	struct lttng_ust_channel_buffer *lttng_chan = event_recorder->chan;
	struct lttng_client_ctx client_ctx;
	int ret, nesting;
	struct lttng_ust_ring_buffer_ctx_private *private_ctx;
	uint32_t event_id;

	event_id = (uint32_t) event_recorder->priv->parent.id;
	client_ctx.chan_ctx = lttng_ust_rcu_dereference(lttng_chan->priv->ctx);
	/* Compute internal size of context structures. */
	ctx_get_struct_size(ctx, client_ctx.chan_ctx, &client_ctx.packet_context_len);

	nesting = lib_ring_buffer_nesting_inc(&client_config);
	if (nesting < 0)
		return -EPERM;

	private_ctx = &URCU_TLS(private_ctx_stack)[nesting];
	memset(private_ctx, 0, sizeof(*private_ctx));
	private_ctx->pub = ctx;
	private_ctx->chan = lttng_chan->priv->rb_chan;

	ctx->priv = private_ctx;

	switch (lttng_chan->priv->header_type) {
	case 1:	/* compact */
		if (event_id > 30)
			private_ctx->rflags |= LTTNG_RFLAG_EXTENDED;
		break;
	case 2:	/* large */
		if (event_id > 65534)
			private_ctx->rflags |= LTTNG_RFLAG_EXTENDED;
		break;
	default:
		WARN_ON_ONCE(1);
	}

	ret = lib_ring_buffer_reserve(&client_config, ctx, &client_ctx);
	if (caa_unlikely(ret))
		goto put;
	if (lib_ring_buffer_backend_get_pages(&client_config, ctx,
			&private_ctx->backend_pages)) {
		ret = -EPERM;
		goto put;
	}
	lttng_write_event_header(&client_config, ctx, &client_ctx, event_id);
	return 0;
put:
	lib_ring_buffer_nesting_dec(&client_config);
	return ret;
}

static
void lttng_event_commit(struct lttng_ust_ring_buffer_ctx *ctx)
{
	lib_ring_buffer_commit(&client_config, ctx);
	lib_ring_buffer_nesting_dec(&client_config);
}

static
void lttng_event_write(struct lttng_ust_ring_buffer_ctx *ctx,
		const void *src, size_t len, size_t alignment)
{
	lttng_ust_ring_buffer_align_ctx(ctx, alignment);
	lib_ring_buffer_write(&client_config, ctx, src, len);
}

static
void lttng_event_strcpy(struct lttng_ust_ring_buffer_ctx *ctx,
		const char *src, size_t len)
{
	lib_ring_buffer_strcpy(&client_config, ctx, src, len, '#');
}

static
void lttng_event_pstrcpy_pad(struct lttng_ust_ring_buffer_ctx *ctx,
		const char *src, size_t len)
{
	lib_ring_buffer_pstrcpy(&client_config, ctx, src, len, '\0');
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
	int shm_fd, wait_fd, wakeup_fd;
	uint64_t memory_map_size;
	void *memory_map_addr;

	if (client_config.alloc == RING_BUFFER_ALLOC_PER_CHANNEL) {
		struct lttng_ust_ring_buffer *buf;

		buf = channel_get_ring_buffer(&client_config, rb_chan,
				0, rb_chan->handle, &shm_fd, &wait_fd,
				&wakeup_fd, &memory_map_size, &memory_map_addr);
		lib_ring_buffer_switch(&client_config, buf,
				SWITCH_ACTIVE, rb_chan->handle);
	} else {
		int cpu;

		for_each_channel_cpu(cpu, rb_chan) {
			struct lttng_ust_ring_buffer *buf;

			buf = channel_get_ring_buffer(&client_config, rb_chan,
					cpu, rb_chan->handle, &shm_fd, &wait_fd,
					&wakeup_fd, &memory_map_size, &memory_map_addr);
			lib_ring_buffer_switch(&client_config, buf,
					SWITCH_ACTIVE, rb_chan->handle);
		}
	}
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
			.packet_avail_size = NULL,	/* Would be racy anyway */
			.is_finalized = lttng_is_finalized,
			.is_disabled = lttng_is_disabled,
			.flush_buffer = lttng_flush_buffer,
		}),
		.event_reserve = lttng_event_reserve,
		.event_commit = lttng_event_commit,
		.event_write = lttng_event_write,
		.event_strcpy = lttng_event_strcpy,
		.event_pstrcpy_pad = lttng_event_pstrcpy_pad,
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
