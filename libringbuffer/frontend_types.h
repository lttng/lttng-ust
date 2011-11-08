#ifndef _LINUX_RING_BUFFER_FRONTEND_TYPES_H
#define _LINUX_RING_BUFFER_FRONTEND_TYPES_H

/*
 * linux/ringbuffer/frontend_types.h
 *
 * (C) Copyright 2005-2010 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Ring Buffer Library Synchronization Header (types).
 *
 * Author:
 *	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * See ring_buffer_frontend.c for more information on wait-free algorithms.
 *
 * Dual LGPL v2.1/GPL v2 license.
 */

#include <string.h>

#include <urcu/list.h>
#include <urcu/uatomic.h>

#include "lttng/core.h"

#include <lttng/usterr-signal-safe.h>
#include <lttng/ringbuffer-config.h>
#include "backend_types.h"
#include "shm_internal.h"

/*
 * A switch is done during tracing or as a final flush after tracing (so it
 * won't write in the new sub-buffer).
 */
enum switch_mode { SWITCH_ACTIVE, SWITCH_FLUSH };

/* channel: collection of per-cpu ring buffers. */
struct channel {
	int record_disabled;
	unsigned long commit_count_mask;	/*
						 * Commit count mask, removing
						 * the MSBs corresponding to
						 * bits used to represent the
						 * subbuffer index.
						 */

	unsigned long switch_timer_interval;	/* Buffer flush (jiffies) */
	unsigned long read_timer_interval;	/* Reader wakeup (jiffies) */
	//wait_queue_head_t read_wait;		/* reader wait queue */
	int finalized;				/* Has channel been finalized */
	size_t priv_data_offset;
	/*
	 * Associated backend contains a variable-length array. Needs to
	 * be last member.
	 */
	struct channel_backend backend;		/* Associated backend */
} ____cacheline_aligned;

/* Per-subbuffer commit counters used on the hot path */
struct commit_counters_hot {
	union v_atomic cc;		/* Commit counter */
	union v_atomic seq;		/* Consecutive commits */
} ____cacheline_aligned;

/* Per-subbuffer commit counters used only on cold paths */
struct commit_counters_cold {
	union v_atomic cc_sb;		/* Incremented _once_ at sb switch */
} ____cacheline_aligned;

/* ring buffer state */
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
	long active_shadow_readers;
					/* Dropped records */
	union v_atomic records_lost_full;	/* Buffer full */
	union v_atomic records_lost_wrap;	/* Nested wrap-around */
	union v_atomic records_lost_big;	/* Events too big */
	union v_atomic records_count;	/* Number of records written */
	union v_atomic records_overrun;	/* Number of overwritten records */
	//wait_queue_head_t read_wait;	/* reader buffer-level wait queue */
	int finalized;			/* buffer has been finalized */
	//struct timer_list switch_timer;	/* timer for periodical switch */
	//struct timer_list read_timer;	/* timer for read poll */
	unsigned long get_subbuf_consumed;	/* Read-side consumed */
	unsigned long prod_snapshot;	/* Producer count snapshot */
	unsigned long cons_snapshot;	/* Consumer count snapshot */
	int get_subbuf:1;		/* Sub-buffer being held by reader */
	int switch_timer_enabled:1;	/* Protected by ring_buffer_nohz_lock */
	int read_timer_enabled:1;	/* Protected by ring_buffer_nohz_lock */
	/* shmp pointer to self */
	DECLARE_SHMP(struct lttng_ust_lib_ring_buffer, self);
} ____cacheline_aligned;

static inline
void *channel_get_private(struct channel *chan)
{
	return ((char *) chan) + chan->priv_data_offset;
}

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
			if (__same_type(*(c), struct channel_backend))	\
				__chan = caa_container_of((void *) (c),	\
							struct channel, \
							backend);	\
			else if (__same_type(*(c), struct channel))	\
				__chan = (void *) (c);			\
			else						\
				BUG_ON(1);				\
			uatomic_inc(&__chan->record_disabled);		\
			WARN_ON(1);					\
		}							\
		_____ret;						\
	})

#endif /* _LINUX_RING_BUFFER_FRONTEND_TYPES_H */
