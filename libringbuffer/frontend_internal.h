#ifndef _LTTNG_RING_BUFFER_FRONTEND_INTERNAL_H
#define _LTTNG_RING_BUFFER_FRONTEND_INTERNAL_H

/*
 * libringbuffer/frontend_internal.h
 *
 * Ring Buffer Library Synchronization Header (internal helpers).
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
 *
 * Author:
 *	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * See ring_buffer_frontend.c for more information on wait-free algorithms.
 *
 * Dual LGPL v2.1/GPL v2 license.
 */

#include <urcu/compiler.h>
#include <urcu/tls-compat.h>
#include <signal.h>
#include <pthread.h>

#include <lttng/ringbuffer-config.h>
#include "backend_types.h"
#include "frontend_types.h"
#include "shm.h"

/* Buffer offset macros */

/* buf_trunc mask selects only the buffer number. */
static inline
unsigned long buf_trunc(unsigned long offset, struct channel *chan)
{
	return offset & ~(chan->backend.buf_size - 1);

}

/* Select the buffer number value (counter). */
static inline
unsigned long buf_trunc_val(unsigned long offset, struct channel *chan)
{
	return buf_trunc(offset, chan) >> chan->backend.buf_size_order;
}

/* buf_offset mask selects only the offset within the current buffer. */
static inline
unsigned long buf_offset(unsigned long offset, struct channel *chan)
{
	return offset & (chan->backend.buf_size - 1);
}

/* subbuf_offset mask selects the offset within the current subbuffer. */
static inline
unsigned long subbuf_offset(unsigned long offset, struct channel *chan)
{
	return offset & (chan->backend.subbuf_size - 1);
}

/* subbuf_trunc mask selects the subbuffer number. */
static inline
unsigned long subbuf_trunc(unsigned long offset, struct channel *chan)
{
	return offset & ~(chan->backend.subbuf_size - 1);
}

/* subbuf_align aligns the offset to the next subbuffer. */
static inline
unsigned long subbuf_align(unsigned long offset, struct channel *chan)
{
	return (offset + chan->backend.subbuf_size)
	       & ~(chan->backend.subbuf_size - 1);
}

/* subbuf_index returns the index of the current subbuffer within the buffer. */
static inline
unsigned long subbuf_index(unsigned long offset, struct channel *chan)
{
	return buf_offset(offset, chan) >> chan->backend.subbuf_size_order;
}

/*
 * Last TSC comparison functions. Check if the current TSC overflows tsc_bits
 * bits from the last TSC read. When overflows are detected, the full 64-bit
 * timestamp counter should be written in the record header. Reads and writes
 * last_tsc atomically.
 */

#if (CAA_BITS_PER_LONG == 32)
static inline
void save_last_tsc(const struct lttng_ust_lib_ring_buffer_config *config,
		   struct lttng_ust_lib_ring_buffer *buf, uint64_t tsc)
{
	if (config->tsc_bits == 0 || config->tsc_bits == 64)
		return;

	/*
	 * Ensure the compiler performs this update in a single instruction.
	 */
	v_set(config, &buf->last_tsc, (unsigned long)(tsc >> config->tsc_bits));
}

static inline
int last_tsc_overflow(const struct lttng_ust_lib_ring_buffer_config *config,
		      struct lttng_ust_lib_ring_buffer *buf, uint64_t tsc)
{
	unsigned long tsc_shifted;

	if (config->tsc_bits == 0 || config->tsc_bits == 64)
		return 0;

	tsc_shifted = (unsigned long)(tsc >> config->tsc_bits);
	if (caa_unlikely(tsc_shifted
		     - (unsigned long)v_read(config, &buf->last_tsc)))
		return 1;
	else
		return 0;
}
#else
static inline
void save_last_tsc(const struct lttng_ust_lib_ring_buffer_config *config,
		   struct lttng_ust_lib_ring_buffer *buf, uint64_t tsc)
{
	if (config->tsc_bits == 0 || config->tsc_bits == 64)
		return;

	v_set(config, &buf->last_tsc, (unsigned long)tsc);
}

static inline
int last_tsc_overflow(const struct lttng_ust_lib_ring_buffer_config *config,
		      struct lttng_ust_lib_ring_buffer *buf, uint64_t tsc)
{
	if (config->tsc_bits == 0 || config->tsc_bits == 64)
		return 0;

	if (caa_unlikely((tsc - v_read(config, &buf->last_tsc))
		     >> config->tsc_bits))
		return 1;
	else
		return 0;
}
#endif

extern
int lib_ring_buffer_reserve_slow(struct lttng_ust_lib_ring_buffer_ctx *ctx);

extern
void lib_ring_buffer_switch_slow(struct lttng_ust_lib_ring_buffer *buf,
				 enum switch_mode mode,
				 struct lttng_ust_shm_handle *handle);

/* Buffer write helpers */

static inline
void lib_ring_buffer_reserve_push_reader(struct lttng_ust_lib_ring_buffer *buf,
					 struct channel *chan,
					 unsigned long offset)
{
	unsigned long consumed_old, consumed_new;

	do {
		consumed_old = uatomic_read(&buf->consumed);
		/*
		 * If buffer is in overwrite mode, push the reader consumed
		 * count if the write position has reached it and we are not
		 * at the first iteration (don't push the reader farther than
		 * the writer). This operation can be done concurrently by many
		 * writers in the same buffer, the writer being at the farthest
		 * write position sub-buffer index in the buffer being the one
		 * which will win this loop.
		 */
		if (caa_unlikely(subbuf_trunc(offset, chan)
			      - subbuf_trunc(consumed_old, chan)
			     >= chan->backend.buf_size))
			consumed_new = subbuf_align(consumed_old, chan);
		else
			return;
	} while (caa_unlikely(uatomic_cmpxchg(&buf->consumed, consumed_old,
					      consumed_new) != consumed_old));
}

static inline
void lib_ring_buffer_vmcore_check_deliver(const struct lttng_ust_lib_ring_buffer_config *config,
					  struct lttng_ust_lib_ring_buffer *buf,
				          unsigned long commit_count,
				          unsigned long idx,
					  struct lttng_ust_shm_handle *handle)
{
	if (config->oops == RING_BUFFER_OOPS_CONSISTENCY)
		v_set(config, &shmp_index(handle, buf->commit_hot, idx)->seq, commit_count);
}

static inline
int lib_ring_buffer_poll_deliver(const struct lttng_ust_lib_ring_buffer_config *config,
				 struct lttng_ust_lib_ring_buffer *buf,
			         struct channel *chan,
				 struct lttng_ust_shm_handle *handle)
{
	unsigned long consumed_old, consumed_idx, commit_count, write_offset;

	consumed_old = uatomic_read(&buf->consumed);
	consumed_idx = subbuf_index(consumed_old, chan);
	commit_count = v_read(config, &shmp_index(handle, buf->commit_cold, consumed_idx)->cc_sb);
	/*
	 * No memory barrier here, since we are only interested
	 * in a statistically correct polling result. The next poll will
	 * get the data is we are racing. The mb() that ensures correct
	 * memory order is in get_subbuf.
	 */
	write_offset = v_read(config, &buf->offset);

	/*
	 * Check that the subbuffer we are trying to consume has been
	 * already fully committed.
	 */

	if (((commit_count - chan->backend.subbuf_size)
	     & chan->commit_count_mask)
	    - (buf_trunc(consumed_old, chan)
	       >> chan->backend.num_subbuf_order)
	    != 0)
		return 0;

	/*
	 * Check that we are not about to read the same subbuffer in
	 * which the writer head is.
	 */
	if (subbuf_trunc(write_offset, chan) - subbuf_trunc(consumed_old, chan)
	    == 0)
		return 0;

	return 1;

}

static inline
int lib_ring_buffer_pending_data(const struct lttng_ust_lib_ring_buffer_config *config,
				 struct lttng_ust_lib_ring_buffer *buf,
				 struct channel *chan)
{
	return !!subbuf_offset(v_read(config, &buf->offset), chan);
}

static inline
unsigned long lib_ring_buffer_get_data_size(const struct lttng_ust_lib_ring_buffer_config *config,
					    struct lttng_ust_lib_ring_buffer *buf,
					    unsigned long idx,
					    struct lttng_ust_shm_handle *handle)
{
	return subbuffer_get_data_size(config, &buf->backend, idx, handle);
}

/*
 * Check if all space reservation in a buffer have been committed. This helps
 * knowing if an execution context is nested (for per-cpu buffers only).
 * This is a very specific ftrace use-case, so we keep this as "internal" API.
 */
static inline
int lib_ring_buffer_reserve_committed(const struct lttng_ust_lib_ring_buffer_config *config,
				      struct lttng_ust_lib_ring_buffer *buf,
				      struct channel *chan,
				      struct lttng_ust_shm_handle *handle)
{
	unsigned long offset, idx, commit_count;

	CHAN_WARN_ON(chan, config->alloc != RING_BUFFER_ALLOC_PER_CPU);
	CHAN_WARN_ON(chan, config->sync != RING_BUFFER_SYNC_PER_CPU);

	/*
	 * Read offset and commit count in a loop so they are both read
	 * atomically wrt interrupts. By deal with interrupt concurrency by
	 * restarting both reads if the offset has been pushed. Note that given
	 * we only have to deal with interrupt concurrency here, an interrupt
	 * modifying the commit count will also modify "offset", so it is safe
	 * to only check for offset modifications.
	 */
	do {
		offset = v_read(config, &buf->offset);
		idx = subbuf_index(offset, chan);
		commit_count = v_read(config, &shmp_index(handle, buf->commit_hot, idx)->cc);
	} while (offset != v_read(config, &buf->offset));

	return ((buf_trunc(offset, chan) >> chan->backend.num_subbuf_order)
		     - (commit_count & chan->commit_count_mask) == 0);
}

static inline
void lib_ring_buffer_wakeup(struct lttng_ust_lib_ring_buffer *buf,
		struct lttng_ust_shm_handle *handle)
{
	int wakeup_fd = shm_get_wakeup_fd(handle, &buf->self._ref);
	sigset_t sigpipe_set, pending_set, old_set;
	int ret, sigpipe_was_pending = 0;

	if (wakeup_fd < 0)
		return;

	/*
	 * Wake-up the other end by writing a null byte in the pipe
	 * (non-blocking).  Important note: Because writing into the
	 * pipe is non-blocking (and therefore we allow dropping wakeup
	 * data, as long as there is wakeup data present in the pipe
	 * buffer to wake up the consumer), the consumer should perform
	 * the following sequence for waiting:
	 * 1) empty the pipe (reads).
	 * 2) check if there is data in the buffer.
	 * 3) wait on the pipe (poll).
	 *
	 * Discard the SIGPIPE from write(), not disturbing any SIGPIPE
	 * that might be already pending. If a bogus SIGPIPE is sent to
	 * the entire process concurrently by a malicious user, it may
	 * be simply discarded.
	 */
	ret = sigemptyset(&pending_set);
	assert(!ret);
	/*
	 * sigpending returns the mask of signals that are _both_
	 * blocked for the thread _and_ pending for either the thread or
	 * the entire process.
	 */
	ret = sigpending(&pending_set);
	assert(!ret);
	sigpipe_was_pending = sigismember(&pending_set, SIGPIPE);
	/*
	 * If sigpipe was pending, it means it was already blocked, so
	 * no need to block it.
	 */
	if (!sigpipe_was_pending) {
		ret = sigemptyset(&sigpipe_set);
		assert(!ret);
		ret = sigaddset(&sigpipe_set, SIGPIPE);
		assert(!ret);
		ret = pthread_sigmask(SIG_BLOCK, &sigpipe_set, &old_set);
		assert(!ret);
	}
	do {
		ret = write(wakeup_fd, "", 1);
	} while (ret == -1L && errno == EINTR);
	if (ret == -1L && errno == EPIPE && !sigpipe_was_pending) {
		struct timespec timeout = { 0, 0 };
		do {
			ret = sigtimedwait(&sigpipe_set, NULL,
				&timeout);
		} while (ret == -1L && errno == EINTR);
	}
	if (!sigpipe_was_pending) {
		ret = pthread_sigmask(SIG_SETMASK, &old_set, NULL);
		assert(!ret);
	}
}

/*
 * Receive end of subbuffer TSC as parameter. It has been read in the
 * space reservation loop of either reserve or switch, which ensures it
 * progresses monotonically with event records in the buffer. Therefore,
 * it ensures that the end timestamp of a subbuffer is <= begin
 * timestamp of the following subbuffers.
 */
static inline
void lib_ring_buffer_check_deliver(const struct lttng_ust_lib_ring_buffer_config *config,
				   struct lttng_ust_lib_ring_buffer *buf,
			           struct channel *chan,
			           unsigned long offset,
				   unsigned long commit_count,
			           unsigned long idx,
				   struct lttng_ust_shm_handle *handle,
				   uint64_t tsc)
{
	unsigned long old_commit_count = commit_count
					 - chan->backend.subbuf_size;

	/* Check if all commits have been done */
	if (caa_unlikely((buf_trunc(offset, chan) >> chan->backend.num_subbuf_order)
		     - (old_commit_count & chan->commit_count_mask) == 0)) {
		/*
		 * If we succeeded at updating cc_sb below, we are the subbuffer
		 * writer delivering the subbuffer. Deals with concurrent
		 * updates of the "cc" value without adding a add_return atomic
		 * operation to the fast path.
		 *
		 * We are doing the delivery in two steps:
		 * - First, we cmpxchg() cc_sb to the new value
		 *   old_commit_count + 1. This ensures that we are the only
		 *   subbuffer user successfully filling the subbuffer, but we
		 *   do _not_ set the cc_sb value to "commit_count" yet.
		 *   Therefore, other writers that would wrap around the ring
		 *   buffer and try to start writing to our subbuffer would
		 *   have to drop records, because it would appear as
		 *   non-filled.
		 *   We therefore have exclusive access to the subbuffer control
		 *   structures.  This mutual exclusion with other writers is
		 *   crucially important to perform record overruns count in
		 *   flight recorder mode locklessly.
		 * - When we are ready to release the subbuffer (either for
		 *   reading or for overrun by other writers), we simply set the
		 *   cc_sb value to "commit_count" and perform delivery.
		 *
		 * The subbuffer size is least 2 bytes (minimum size: 1 page).
		 * This guarantees that old_commit_count + 1 != commit_count.
		 */

		/*
		 * Order prior updates to reserve count prior to the
		 * commit_cold cc_sb update.
		 */
		cmm_smp_wmb();
		if (caa_likely(v_cmpxchg(config, &shmp_index(handle, buf->commit_cold, idx)->cc_sb,
					 old_commit_count, old_commit_count + 1)
			   == old_commit_count)) {
			/*
			 * Start of exclusive subbuffer access. We are
			 * guaranteed to be the last writer in this subbuffer
			 * and any other writer trying to access this subbuffer
			 * in this state is required to drop records.
			 */
			v_add(config,
			      subbuffer_get_records_count(config,
							  &buf->backend,
							  idx, handle),
			      &buf->records_count);
			v_add(config,
			      subbuffer_count_records_overrun(config,
							      &buf->backend,
							      idx, handle),
			      &buf->records_overrun);
			config->cb.buffer_end(buf, tsc, idx,
					      lib_ring_buffer_get_data_size(config,
									buf,
									idx,
									handle),
					      handle);

			/*
			 * Increment the packet counter while we have exclusive
			 * access.
			 */
			subbuffer_inc_packet_count(config, &buf->backend, idx, handle);

			/*
			 * Set noref flag and offset for this subbuffer id.
			 * Contains a memory barrier that ensures counter stores
			 * are ordered before set noref and offset.
			 */
			lib_ring_buffer_set_noref_offset(config, &buf->backend, idx,
							 buf_trunc_val(offset, chan), handle);

			/*
			 * Order set_noref and record counter updates before the
			 * end of subbuffer exclusive access. Orders with
			 * respect to writers coming into the subbuffer after
			 * wrap around, and also order wrt concurrent readers.
			 */
			cmm_smp_mb();
			/* End of exclusive subbuffer access */
			v_set(config, &shmp_index(handle, buf->commit_cold, idx)->cc_sb,
			      commit_count);
			/*
			 * Order later updates to reserve count after
			 * the commit cold cc_sb update.
			 */
			cmm_smp_wmb();
			lib_ring_buffer_vmcore_check_deliver(config, buf,
						 commit_count, idx, handle);

			/*
			 * RING_BUFFER_WAKEUP_BY_WRITER wakeup is not lock-free.
			 */
			if (config->wakeup == RING_BUFFER_WAKEUP_BY_WRITER
			    && uatomic_read(&buf->active_readers)
			    && lib_ring_buffer_poll_deliver(config, buf, chan, handle)) {
				lib_ring_buffer_wakeup(buf, handle);
			}
		}
	}
}

/*
 * lib_ring_buffer_write_commit_counter
 *
 * For flight recording. must be called after commit.
 * This function increments the subbuffer's commit_seq counter each time the
 * commit count reaches back the reserve offset (modulo subbuffer size). It is
 * useful for crash dump.
 */
static inline
void lib_ring_buffer_write_commit_counter(const struct lttng_ust_lib_ring_buffer_config *config,
					  struct lttng_ust_lib_ring_buffer *buf,
				          struct channel *chan,
				          unsigned long idx,
				          unsigned long buf_offset,
				          unsigned long commit_count,
					  struct lttng_ust_shm_handle *handle)
{
	unsigned long commit_seq_old;

	if (config->oops != RING_BUFFER_OOPS_CONSISTENCY)
		return;

	/*
	 * subbuf_offset includes commit_count_mask. We can simply
	 * compare the offsets within the subbuffer without caring about
	 * buffer full/empty mismatch because offset is never zero here
	 * (subbuffer header and record headers have non-zero length).
	 */
	if (caa_unlikely(subbuf_offset(buf_offset - commit_count, chan)))
		return;

	commit_seq_old = v_read(config, &shmp_index(handle, buf->commit_hot, idx)->seq);
	while ((long) (commit_seq_old - commit_count) < 0)
		commit_seq_old = v_cmpxchg(config, &shmp_index(handle, buf->commit_hot, idx)->seq,
					   commit_seq_old, commit_count);
}

extern int lib_ring_buffer_create(struct lttng_ust_lib_ring_buffer *buf,
				  struct channel_backend *chanb, int cpu,
				  struct lttng_ust_shm_handle *handle,
				  struct shm_object *shmobj);
extern void lib_ring_buffer_free(struct lttng_ust_lib_ring_buffer *buf,
				 struct lttng_ust_shm_handle *handle);

/* Keep track of trap nesting inside ring buffer code */
extern DECLARE_URCU_TLS(unsigned int, lib_ring_buffer_nesting);

#endif /* _LTTNG_RING_BUFFER_FRONTEND_INTERNAL_H */
