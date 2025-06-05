/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2005-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Ring Buffer Library Synchronization Header (types).
 *
 * See ring_buffer_frontend.c for more information on wait-free algorithms.
 */

#ifndef _LTTNG_RING_BUFFER_FRONTEND_TYPES_H
#define _LTTNG_RING_BUFFER_FRONTEND_TYPES_H

#include <stdint.h>
#include <string.h>
#include <time.h>	/* for timer_t */

#include <urcu/list.h>
#include <urcu/uatomic.h>

#include <lttng/ust-ringbuffer-context.h>
#include "ringbuffer-config.h"
#include "common/logging.h"
#include "backend_types.h"
#include "shm_internal.h"
#include "shm_types.h"
#include "vatomic.h"

#define LIB_RING_BUFFER_MAX_NESTING	5

/*
 * A switch is done during tracing or as a final flush after tracing (so it
 * won't write in the new sub-buffer).
 */
enum switch_mode { SWITCH_ACTIVE, SWITCH_FLUSH };

/* channel: collection of per-cpu ring buffers. */
#define RB_CHANNEL_PADDING		32
struct lttng_ust_ring_buffer_channel {
	int record_disabled;
	unsigned long commit_count_mask;	/*
						 * Commit count mask, removing
						 * the MSBs corresponding to
						 * bits used to represent the
						 * subbuffer index.
						 */

	unsigned long switch_timer_interval;	/* Buffer flush (us) */
	timer_t switch_timer;
	int switch_timer_enabled;

	unsigned long read_timer_interval;	/* Reader wakeup (us) */
	timer_t read_timer;
	int read_timer_enabled;

	int finalized;				/* Has channel been finalized */
	size_t priv_data_offset;		/* Offset of private data channel config */
	unsigned int nr_streams;		/* Number of streams */
	struct lttng_ust_shm_handle *handle;
	/* Extended options. */
	union {
		struct {
			int32_t blocking_timeout_ms;
			void *priv;		/* Private data pointer. */
		} s;
		char padding[RB_CHANNEL_PADDING];
	} u;
	/*
	 * Associated backend contains a variable-length array. Needs to
	 * be last member.
	 */
	struct channel_backend backend;		/* Associated backend */
} __attribute__((aligned(CAA_CACHE_LINE_SIZE)));

/* Per-subbuffer commit counters used on the hot path */
#define RB_COMMIT_COUNT_HOT_PADDING	16
struct commit_counters_hot {
	union v_atomic cc;		/* Commit counter */
	union v_atomic seq;		/* Consecutive commits */
	char padding[RB_COMMIT_COUNT_HOT_PADDING];
} __attribute__((aligned(CAA_CACHE_LINE_SIZE)));

/* Per-subbuffer commit counters used only on cold paths */
#define RB_COMMIT_COUNT_COLD_PADDING	24
struct commit_counters_cold {
	union v_atomic cc_sb;		/* Incremented _once_ at sb switch */
	union {
		unsigned long end_events_discarded; /*
						     * Passing events discarded counter
						     * read upon try_reserve and try_switch
						     * that fills a subbuffer to check_deliver
						     * so it can be written into the packet
						     * header field.
						     */
		char padding[RB_COMMIT_COUNT_COLD_PADDING];
	};
} __attribute__((aligned(CAA_CACHE_LINE_SIZE)));

/* ring buffer state */
#define RB_CRASH_DUMP_ABI_LEN		256
#define RB_RING_BUFFER_PADDING		60

#define RB_CRASH_DUMP_ABI_MAGIC_LEN	16

/*
 * The 128-bit magic number is xor'd in the process data so it does not
 * cause a false positive when searching for buffers by scanning memory.
 * The actual magic number is:
 *   0x17, 0x7B, 0xF1, 0x77, 0xBF, 0x17, 0x7B, 0xF1,
 *   0x77, 0xBF, 0x17, 0x7B, 0xF1, 0x77, 0xBF, 0x17,
 */
#define RB_CRASH_DUMP_ABI_MAGIC_XOR					\
	{								\
		0x17 ^ 0xFF, 0x7B ^ 0xFF, 0xF1 ^ 0xFF, 0x77 ^ 0xFF,	\
		0xBF ^ 0xFF, 0x17 ^ 0xFF, 0x7B ^ 0xFF, 0xF1 ^ 0xFF,	\
		0x77 ^ 0xFF, 0xBF ^ 0xFF, 0x17 ^ 0xFF, 0x7B ^ 0xFF,	\
		0xF1 ^ 0xFF, 0x77 ^ 0xFF, 0xBF ^ 0xFF, 0x17 ^ 0xFF,	\
	}

#define RB_CRASH_ENDIAN			0x1234

#define RB_CRASH_DUMP_ABI_MAJOR		0
#define RB_CRASH_DUMP_ABI_MINOR		0

enum lttng_crash_type {
	LTTNG_CRASH_TYPE_UST = 0,
	LTTNG_CRASH_TYPE_KERNEL = 1,
};

struct lttng_crash_abi {
	uint8_t magic[RB_CRASH_DUMP_ABI_MAGIC_LEN];
	uint64_t mmap_length;	/* Overall length of crash record */
	uint16_t endian;	/*
				 * { 0x12, 0x34 }: big endian
				 * { 0x34, 0x12 }: little endian
				 */
	uint16_t major;		/* Major number. */
	uint16_t minor;		/* Minor number. */
	uint8_t word_size;	/* Word size (bytes). */
	uint8_t layout_type;	/* enum lttng_crash_type */

	struct {
		uint32_t prod_offset;
		uint32_t consumed_offset;
		uint32_t commit_hot_array;
		uint32_t commit_hot_seq;
		uint32_t buf_wsb_array;
		uint32_t buf_wsb_id;
		uint32_t sb_array;
		uint32_t sb_array_shmp_offset;
		uint32_t sb_backend_p_offset;
		uint32_t content_size;
		uint32_t packet_size;
	} __attribute__((packed)) offset;
	struct {
		uint8_t prod_offset;
		uint8_t consumed_offset;
		uint8_t commit_hot_seq;
		uint8_t buf_wsb_id;
		uint8_t sb_array_shmp_offset;
		uint8_t sb_backend_p_offset;
		uint8_t content_size;
		uint8_t packet_size;
	} __attribute__((packed)) length;
	struct {
		uint32_t commit_hot_array;
		uint32_t buf_wsb_array;
		uint32_t sb_array;
	} __attribute__((packed)) stride;

	uint64_t buf_size;	/* Size of the buffer */
	uint64_t subbuf_size;	/* Sub-buffer size */
	uint64_t num_subbuf;	/* Number of sub-buffers for writer */
	uint32_t mode;		/* Buffer mode: 0: overwrite, 1: discard */
} __attribute__((packed));

struct lttng_ust_ring_buffer {
	/* First 32 bytes are for the buffer crash dump ABI */
	struct lttng_crash_abi crash_abi;

	/* 32 bytes cache-hot cacheline */
	union v_atomic __attribute__((aligned(32))) offset;
					/* Current offset in the buffer */
	DECLARE_SHMP(struct commit_counters_hot, commit_hot);
					/* Commit count per sub-buffer */
	long consumed;			/*
					 * Current offset in the buffer
					 * standard atomic access (shared)
					 */
	int record_disabled;
	/* End of cache-hot 32 bytes cacheline */

	union v_atomic last_timestamp;	/*
					 * Last timestamp written in the buffer.
					 */

	struct lttng_ust_ring_buffer_backend backend;
					/* Associated backend */

	DECLARE_SHMP(struct commit_counters_cold, commit_cold);
					/* Commit count per sub-buffer */
	DECLARE_SHMP(uint64_t, ts_end);	/*
					 * timestamp_end per sub-buffer.
					 * Time is sampled by the
					 * switch_*_end() callbacks
					 * which are the last space
					 * reservation performed in the
					 * sub-buffer before it can be
					 * fully committed and
					 * delivered. This time value is
					 * then read by the deliver
					 * callback, performed by the
					 * last commit before the buffer
					 * becomes readable.
					 */
	long active_readers;		/*
					 * Active readers count
					 * standard atomic access (shared)
					 */
					/* Dropped records */
	union v_atomic records_lost_full;	/* Buffer full */
	union v_atomic records_lost_wrap;	/* Nested wrap-around */
	union v_atomic records_lost_big;	/* Events too big */
	union v_atomic records_count;	/* Number of records written */
	union v_atomic records_overrun;	/* Number of overwritten records */
	//wait_queue_head_t read_wait;	/* reader buffer-level wait queue */
	int finalized;			/* buffer has been finalized */
	unsigned long get_subbuf_consumed;	/* Read-side consumed */
	unsigned long prod_snapshot;	/* Producer count snapshot */
	unsigned long cons_snapshot;	/* Consumer count snapshot */
	unsigned int get_subbuf:1;	/* Sub-buffer being held by reader */
	/* shmp pointer to self */
	DECLARE_SHMP(struct lttng_ust_ring_buffer, self);
	char padding[RB_RING_BUFFER_PADDING];
} __attribute__((aligned(CAA_CACHE_LINE_SIZE)));

/*
 * ring buffer private context
 *
 * Private context passed to lib_ring_buffer_reserve(), lib_ring_buffer_commit(),
 * lib_ring_buffer_try_discard_reserve(), lttng_ust_ring_buffer_align_ctx() and
 * lib_ring_buffer_write().
 *
 * This context is allocated on an internal shadow-stack by a successful reserve
 * operation, used by align/write, and freed by commit.
 */

struct lttng_ust_ring_buffer_ctx_private {
	/* input received by lib_ring_buffer_reserve(). */
	struct lttng_ust_ring_buffer_ctx *pub;
	struct lttng_ust_ring_buffer_channel *chan; /* channel */

	/* output from lib_ring_buffer_reserve() */
	int reserve_cpu;			/* processor id updated by the reserve */
	size_t slot_size;			/* size of the reserved slot */
	unsigned long buf_offset;		/* offset following the record header */
	unsigned long pre_offset;		/*
						 * Initial offset position _before_
						 * the record is written. Positioned
						 * prior to record header alignment
						 * padding.
						 */
	uint64_t timestamp;			/* time-stamp counter value */
	unsigned int rflags;			/* reservation flags */
	struct lttng_ust_ring_buffer *buf;	/*
						 * buffer corresponding to processor id
						 * for this channel
						 */
	struct lttng_ust_ring_buffer_backend_pages *backend_pages;

	/*
	 * Records lost counts are only loaded into these fields before
	 * reserving the last bytes from the ring buffer.
	 */
	unsigned long records_lost_full;
	unsigned long records_lost_wrap;
	unsigned long records_lost_big;
};

static inline
void *channel_get_private_config(struct lttng_ust_ring_buffer_channel *chan)
{
	return ((char *) chan) + chan->priv_data_offset;
}

static inline
void *channel_get_private(struct lttng_ust_ring_buffer_channel *chan)
{
	return chan->u.s.priv;
}

static inline
void channel_set_private(struct lttng_ust_ring_buffer_channel *chan, void *priv)
{
	chan->u.s.priv = priv;
}

#ifndef __rb_same_type
#define __rb_same_type(a, b)	__builtin_types_compatible_p(typeof(a), typeof(b))
#endif

/*
 * Issue warnings and disable channels upon internal error.
 * Can receive struct lttng_ust_ring_buffer or struct lttng_ust_ring_buffer_backend
 * parameters.
 */
#define CHAN_WARN_ON(c, cond)						\
	({								\
		struct lttng_ust_ring_buffer_channel *__chan;	\
		int _____ret = caa_unlikely(cond);				\
		if (_____ret) {						\
			if (__rb_same_type(*(c), struct channel_backend))	\
				__chan = caa_container_of((void *) (c),	\
					struct lttng_ust_ring_buffer_channel, \
					backend);			\
			else if (__rb_same_type(*(c),			\
					struct lttng_ust_ring_buffer_channel)) \
				__chan = (void *) (c);			\
			else						\
				BUG_ON(1);				\
			uatomic_inc(&__chan->record_disabled);		\
			WARN_ON(1);					\
		}							\
		_____ret = _____ret; /* For clang "unused result". */	\
	})

/**
 * lttng_ust_ring_buffer_align_ctx - Align context offset on "alignment"
 * @ctx: ring buffer context.
 */
static inline
void lttng_ust_ring_buffer_align_ctx(struct lttng_ust_ring_buffer_ctx *ctx,
			   size_t alignment)
	lttng_ust_notrace;
static inline
void lttng_ust_ring_buffer_align_ctx(struct lttng_ust_ring_buffer_ctx *ctx,
			   size_t alignment)
{
	struct lttng_ust_ring_buffer_ctx_private *ctx_private = ctx->priv;

	ctx_private->buf_offset += lttng_ust_ring_buffer_align(ctx_private->buf_offset,
						 alignment);
}

#endif /* _LTTNG_RING_BUFFER_FRONTEND_TYPES_H */
