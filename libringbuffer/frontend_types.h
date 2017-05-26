#ifndef _LTTNG_RING_BUFFER_FRONTEND_TYPES_H
#define _LTTNG_RING_BUFFER_FRONTEND_TYPES_H

/*
 * libringbuffer/frontend_types.h
 *
 * Ring Buffer Library Synchronization Header (types).
 *
 * Copyright (C) 2005-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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
 *
 * Author:
 *	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * See ring_buffer_frontend.c for more information on wait-free algorithms.
 */

#include <string.h>
#include <time.h>	/* for timer_t */

#include <urcu/list.h>
#include <urcu/uatomic.h>

#include <lttng/ringbuffer-config.h>
#include <usterr-signal-safe.h>
#include "backend_types.h"
#include "shm_internal.h"
#include "shm_types.h"
#include "vatomic.h"

/*
 * A switch is done during tracing or as a final flush after tracing (so it
 * won't write in the new sub-buffer).
 */
enum switch_mode { SWITCH_ACTIVE, SWITCH_FLUSH };

/* channel: collection of per-cpu ring buffers. */
#define RB_CHANNEL_PADDING		32
struct channel {
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
	size_t priv_data_offset;
	unsigned int nr_streams;		/* Number of streams */
	struct lttng_ust_shm_handle *handle;
	/* Extended options. */
	union {
		struct {
			int32_t blocking_timeout_ms;
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
	char padding[RB_COMMIT_COUNT_COLD_PADDING];
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
	uint64_t mmap_length;	/* Overall lenght of crash record */
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

struct lttng_ust_lib_ring_buffer {
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

	union v_atomic last_tsc;	/*
					 * Last timestamp written in the buffer.
					 */

	struct lttng_ust_lib_ring_buffer_backend backend;
					/* Associated backend */

	DECLARE_SHMP(struct commit_counters_cold, commit_cold);
					/* Commit count per sub-buffer */
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
	DECLARE_SHMP(struct lttng_ust_lib_ring_buffer, self);
	char padding[RB_RING_BUFFER_PADDING];
} __attribute__((aligned(CAA_CACHE_LINE_SIZE)));

static inline
void *channel_get_private(struct channel *chan)
{
	return ((char *) chan) + chan->priv_data_offset;
}

#ifndef __rb_same_type
#define __rb_same_type(a, b)	__builtin_types_compatible_p(typeof(a), typeof(b))
#endif

/*
 * Issue warnings and disable channels upon internal error.
 * Can receive struct lttng_ust_lib_ring_buffer or struct lttng_ust_lib_ring_buffer_backend
 * parameters.
 */
#define CHAN_WARN_ON(c, cond)						\
	({								\
		struct channel *__chan;					\
		int _____ret = caa_unlikely(cond);				\
		if (_____ret) {						\
			if (__rb_same_type(*(c), struct channel_backend))	\
				__chan = caa_container_of((void *) (c),	\
							struct channel, \
							backend);	\
			else if (__rb_same_type(*(c), struct channel))	\
				__chan = (void *) (c);			\
			else						\
				BUG_ON(1);				\
			uatomic_inc(&__chan->record_disabled);		\
			WARN_ON(1);					\
		}							\
		_____ret = _____ret; /* For clang "unused result". */	\
	})

#endif /* _LTTNG_RING_BUFFER_FRONTEND_TYPES_H */
