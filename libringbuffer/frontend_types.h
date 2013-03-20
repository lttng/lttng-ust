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
	char padding[RB_CHANNEL_PADDING];
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
#define RB_RING_BUFFER_PADDING		64
struct lttng_ust_lib_ring_buffer {
	/* First 32 bytes cache-hot cacheline */
	union v_atomic offset;		/* Current offset in the buffer */
	DECLARE_SHMP(struct commit_counters_hot, commit_hot);
					/* Commit count per sub-buffer */
	long consumed;			/*
					 * Current offset in the buffer
					 * standard atomic access (shared)
					 */
	int record_disabled;
	/* End of first 32 bytes cacheline */
	union v_atomic last_tsc;	/*
					 * Last timestamp written in the buffer.
					 */

	struct lttng_ust_lib_ring_buffer_backend backend;	/* Associated backend */

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
