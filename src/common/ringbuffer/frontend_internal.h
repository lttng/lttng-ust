/*
 * SPDX-License-Identifier: (LGPL-2.1-only or GPL-2.0-only)
 *
 * Copyright (C) 2005-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Ring Buffer Library Synchronization Header (internal helpers).
 *
 * See ring_buffer_frontend.c for more information on wait-free algorithms.
 */

#ifndef _LTTNG_RING_BUFFER_FRONTEND_INTERNAL_H
#define _LTTNG_RING_BUFFER_FRONTEND_INTERNAL_H

#include <urcu/compiler.h>
#include <urcu/tls-compat.h>
#include <signal.h>
#include <stdint.h>
#include <pthread.h>

#include <lttng/ust-ringbuffer-context.h>
#include "common/testpoint.h"
#include "ringbuffer-config.h"
#include "backend_types.h"
#include "backend_internal.h"
#include "frontend_types.h"
#include "shm.h"

/* Buffer offset macros */

/* buf_trunc mask selects only the buffer number. */
static inline
unsigned long buf_trunc(unsigned long offset,
			struct lttng_ust_ring_buffer_channel *chan)
{
	return offset & ~(chan->backend.buf_size - 1);

}

/* Select the buffer number value (counter). */
static inline
unsigned long buf_trunc_val(unsigned long offset,
			struct lttng_ust_ring_buffer_channel *chan)
{
	return buf_trunc(offset, chan) >> chan->backend.buf_size_order;
}

/* buf_offset mask selects only the offset within the current buffer. */
static inline
unsigned long buf_offset(unsigned long offset,
			struct lttng_ust_ring_buffer_channel *chan)
{
	return offset & (chan->backend.buf_size - 1);
}

/* subbuf_offset mask selects the offset within the current subbuffer. */
static inline
unsigned long subbuf_offset(unsigned long offset,
			struct lttng_ust_ring_buffer_channel *chan)
{
	return offset & (chan->backend.subbuf_size - 1);
}

/* subbuf_trunc mask selects the subbuffer number. */
static inline
unsigned long subbuf_trunc(unsigned long offset,
			struct lttng_ust_ring_buffer_channel *chan)
{
	return offset & ~(chan->backend.subbuf_size - 1);
}

/* subbuf_align aligns the offset to the next subbuffer. */
static inline
unsigned long subbuf_align(unsigned long offset,
			struct lttng_ust_ring_buffer_channel *chan)
{
	return (offset + chan->backend.subbuf_size)
	       & ~(chan->backend.subbuf_size - 1);
}

/* subbuf_index returns the index of the current subbuffer within the buffer. */
static inline
unsigned long subbuf_index(unsigned long offset,
			struct lttng_ust_ring_buffer_channel *chan)
{
	return buf_offset(offset, chan) >> chan->backend.subbuf_size_order;
}

/*
 * subbuf_fill_reserve returns the reservation position to fill the sub-buffer
 * given the value of `hot' in sub-buffer at index `subbuf_idx'.
 *
 * Examples:
 *
 *  subbuf_fill_reserve(0, 0) => subbuf_size
 *  subbuf_fill_reserve(1, 0) => subbuf_size
 *  subbuf_fill_reserve(subbuf_size, 0) => buf_size + subbuf_size
 *  subbuf_fill_reserve(subbuf_size + 1, 0) => buf_size + subbuf_size
 *
 *  subbuf_fill_reserve(0, 1) => 2 * subbuf_size
 *  subbuf_fill_reserve(1, 1) => 2 * subbuf_size
 *  subbuf_fill_reserve(subbuf_size, 1) => buf_size + 2 * subbuf_size
 *  subbuf_fill_reserve(subbuf_size + 1, 1) => buf_size + 2 * subbuf_size
 */
static inline
unsigned long subbuf_fill_reserve(unsigned long hot,
				unsigned long subbuf_idx,
				struct lttng_ust_ring_buffer_channel *chan)
{
	return ((((subbuf_align(hot, chan) >> chan->backend.subbuf_size_order) - 1) << chan->backend.buf_size_order)
		+ (subbuf_idx << chan->backend.subbuf_size_order)
		+ chan->backend.subbuf_size);
}

/*
 * subbuf_minimum_reserve returns the minimal reservation position given the
 * value of `hot' in sub-buffer at index `subbuf_idx'.
 *
 * Examples:
 *
 *  subbuf_minimum_reserve(0, 0) => 0
 *  subbuf_minimum_reserve(1, 0) => 1
 *  subbuf_minimum_reserve(subbuf_size, 0) => buf_size
 *  subbuf_minimum_reserve(subbuf_size + 1, 0) => buf_size + 1
 *
 *  subbuf_minimum_reserve(0, 1) => subbuf_size
 *  subbuf_minimum_reserve(1, 1) => subbuf_size + 1
 *  subbuf_minimum_reserve(subbuf_size, 1) => buf_size + subbuf_size
 *  subbuf_minimum_reserve(subbuf_size + 1, 1) => buf_size + subbuf_size + 1
 */
static inline
unsigned long subbuf_minimum_reserve(unsigned long hot,
				unsigned long subbuf_idx,
				struct lttng_ust_ring_buffer_channel *chan)
{
	return ((((subbuf_trunc(hot, chan) >> chan->backend.subbuf_size_order)) << chan->backend.buf_size_order)
		+ (subbuf_idx << chan->backend.subbuf_size_order)
		+ subbuf_offset(hot, chan));
}

/*
 * Last timestamp comparison functions. Check if the current timestamp overflows
 * timestamp_bits bits from the last timestamp read. When overflows are
 * detected, the full 64-bit timestamp counter should be written in the record
 * header. Reads and writes last_timestamp atomically.
 */

#if (CAA_BITS_PER_LONG == 32)
static inline
void save_last_timestamp(const struct lttng_ust_ring_buffer_config *config,
		   struct lttng_ust_ring_buffer_channel *chan,
		   struct lttng_ust_ring_buffer *buf, uint64_t timestamp)
{
	unsigned int activity_timestamp_bits = chan->u.s.activity_timestamp_bits;

	/*
	 * Ensure the compiler performs each update in a single instruction.
	 */
	if (config->timestamp_bits < 64)
		v_set(config, &buf->last_timestamp, (unsigned long)(timestamp >> config->timestamp_bits));
	if (activity_timestamp_bits < 64)
		v_set(config, &buf->u.last_activity_timestamp, (unsigned long)(timestamp >> chan->u.s.activity_timestamp_bits));
}

static inline
int last_timestamp_overflow(const struct lttng_ust_ring_buffer_config *config,
		      struct lttng_ust_ring_buffer *buf, uint64_t timestamp)
{
	unsigned long timestamp_shifted;

	if (config->timestamp_bits == 0 || config->timestamp_bits >= 64)
		return 0;

	timestamp_shifted = (unsigned long)(timestamp >> config->timestamp_bits);
	if (caa_unlikely(timestamp_shifted
		     - (unsigned long)v_read(config, &buf->last_timestamp)))
		return 1;
	else
		return 0;
}

static inline
int last_activity_timestamp_compare(const struct lttng_ust_ring_buffer_config *config,
		      struct lttng_ust_ring_buffer_channel *chan,
		      struct lttng_ust_ring_buffer *buf, uint64_t timestamp)
{
	unsigned int activity_timestamp_bits = chan->u.s.activity_timestamp_bits;
	unsigned long timestamp_shifted;
	long res;

	if (activity_timestamp_bits >= 64)
		return 0;

	timestamp_shifted = (unsigned long)(timestamp >> activity_timestamp_bits);
	res = (long)((unsigned long)v_read(config, &buf->u.last_activity_timestamp) - timestamp_shifted);
	if (res < 0)
		return -1;
	else if (res > 0)
		return 1;
	else
		return 0;
}
#else
static inline
void save_last_timestamp(const struct lttng_ust_ring_buffer_config *config,
		   struct lttng_ust_ring_buffer_channel *chan __attribute__((unused)),
		   struct lttng_ust_ring_buffer *buf, uint64_t timestamp)
{
	v_set(config, &buf->last_timestamp, (unsigned long)timestamp);
}

static inline
int last_timestamp_overflow(const struct lttng_ust_ring_buffer_config *config,
		      struct lttng_ust_ring_buffer *buf, uint64_t timestamp)
{
	if (config->timestamp_bits == 0 || config->timestamp_bits >= 64)
		return 0;

	if (caa_unlikely((timestamp - v_read(config, &buf->last_timestamp))
		     >> config->timestamp_bits))
		return 1;
	else
		return 0;
}

static inline
int last_activity_timestamp_compare(const struct lttng_ust_ring_buffer_config *config,
		      struct lttng_ust_ring_buffer_channel *chan __attribute__((unused)),
		      struct lttng_ust_ring_buffer *buf, uint64_t timestamp)
{
	int64_t res;

	res = (int64_t)((uint64_t)v_read(config, &buf->last_timestamp) - timestamp);
	if (res < 0)
		return -1;
	else if (res > 0)
		return 1;
	else
		return 0;
}
#endif

extern
int lib_ring_buffer_reserve_slow(struct lttng_ust_ring_buffer_ctx *ctx,
		void *client_ctx)
	__attribute__((visibility("hidden")));

extern
void lib_ring_buffer_switch_slow(struct lttng_ust_ring_buffer *buf,
				 enum switch_mode mode,
				 unsigned long *old_pos,
				 struct lttng_ust_shm_handle *handle)
	__attribute__((visibility("hidden")));

void lib_ring_buffer_check_deliver_slow(const struct lttng_ust_ring_buffer_config *config,
				   struct lttng_ust_ring_buffer *buf,
			           struct lttng_ust_ring_buffer_channel *chan,
			           unsigned long offset,
				   unsigned long commit_count,
			           unsigned long idx,
				   struct lttng_ust_shm_handle *handle,
				   const struct lttng_ust_ring_buffer_ctx *ctx)
	__attribute__((visibility("hidden")));

extern void lib_ring_buffer_wakeup(struct lttng_ust_ring_buffer *buf,
		struct lttng_ust_shm_handle *handle)
	__attribute__((visibility("hidden")));

/* Buffer write helpers */

static inline
void lib_ring_buffer_reserve_push_reader(const struct lttng_ust_ring_buffer_config *config __attribute__((unused)),
					struct lttng_ust_ring_buffer *buf,
					struct lttng_ust_ring_buffer_channel *chan,
					unsigned long offset)
{
	unsigned long consumed_old, consumed_new;

	do {
		consumed_old = uatomic_read(&buf->consumed);
		/*
		 * If buffer is in overwrite mode, push the reader consumed
		 * count if the write position has reached it and we are not at
		 * the first iteration (don't push the reader farther than the
		 * writer). This operation can be done concurrently by many
		 * writers in the same buffer.
		 */
		if (caa_unlikely(subbuf_trunc(offset, chan)
			      - subbuf_trunc(consumed_old, chan)
			     >= chan->backend.buf_size))
			/*
			 * At this point, it is sure that `offset` is greater or
			 * equal to `buf_size`. Thus `subbuf_trunc(offset) -
			 * buf_size` is greater or equal to zero.
			 *
			 * The computation of the new consumed position is made
			 * by calculating the exact distance of `buf_size` from
			 * the truncation of `offset` minus `buf_size`, plus a
			 * `subbuf_size`. The later is required because of the
			 * sub-buffer truncation.
			 */
			consumed_new = (subbuf_trunc(offset, chan) -
					chan->backend.buf_size +
					chan->backend.subbuf_size);
		else
			return;
		/*
		 * This path is only reachable from overwrite mode buffers.
		 */
		assert(config->mode == RING_BUFFER_OVERWRITE);
	} while (caa_unlikely(uatomic_cmpxchg(&buf->consumed, consumed_old,
					      consumed_new) != consumed_old));
}

/*
 * Move consumed position to the beginning of subbuffer in which the
 * write offset is. Should only be used on ring buffers that are not
 * actively being written into, because clear_reader does not take into
 * account the commit counters when moving the consumed position, which
 * can make concurrent trace producers or consumers observe consumed
 * position further than the write offset, which breaks ring buffer
 * algorithm guarantees.
 */
static inline
void lib_ring_buffer_clear_reader(struct lttng_ust_ring_buffer *buf,
				  struct lttng_ust_shm_handle *handle)
{
	struct lttng_ust_ring_buffer_channel *chan;
	const struct lttng_ust_ring_buffer_config *config;
	unsigned long offset, consumed_old, consumed_new;

	chan = shmp(handle, buf->backend.chan);
	if (!chan)
		return;
	config = &chan->backend.config;

	do {
		offset = v_read(config, &buf->offset);
		consumed_old = uatomic_read(&buf->consumed);
		CHAN_WARN_ON(chan, (long) (subbuf_trunc(offset, chan)
				- subbuf_trunc(consumed_old, chan))
				< 0);
		consumed_new = subbuf_trunc(offset, chan);
	} while (caa_unlikely(uatomic_cmpxchg(&buf->consumed, consumed_old,
					      consumed_new) != consumed_old));
}

static inline
void lib_ring_buffer_timestamp_sync(struct lttng_ust_ring_buffer *buf,
				    struct lttng_ust_shm_handle *handle)
{
	if (!uatomic_read(&buf->use_creation_timestamp))
		return;
	lib_ring_buffer_switch_slow(buf, SWITCH_FLUSH, NULL, handle);
}

static inline
int lib_ring_buffer_pending_data(const struct lttng_ust_ring_buffer_config *config,
				 struct lttng_ust_ring_buffer *buf,
				 struct lttng_ust_ring_buffer_channel *chan)
{
	return !!subbuf_offset(v_read(config, &buf->offset), chan);
}

static inline
unsigned long lib_ring_buffer_get_data_size(const struct lttng_ust_ring_buffer_config *config,
					    struct lttng_ust_ring_buffer *buf,
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
int lib_ring_buffer_reserve_committed(const struct lttng_ust_ring_buffer_config *config,
				      struct lttng_ust_ring_buffer *buf,
				      struct lttng_ust_ring_buffer_channel *chan,
				      struct lttng_ust_shm_handle *handle)
{
	unsigned long offset, idx, commit_count;
	struct commit_counters_hot *cc_hot;

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
		cc_hot = shmp_index(handle, buf->commit_hot, idx);
		if (caa_unlikely(!cc_hot))
			return 0;
		commit_count = v_read(config, &cc_hot->cc);
	} while (offset != v_read(config, &buf->offset));

	return ((buf_trunc(offset, chan) >> chan->backend.num_subbuf_order)
		     - (commit_count & chan->commit_count_mask) == 0);
}

/*
 * Receive end of subbuffer timestamp as parameter. It has been read in the
 * space reservation loop of either reserve or switch, which ensures it
 * progresses monotonically with event records in the buffer. Therefore,
 * it ensures that the end timestamp of a subbuffer is <= begin
 * timestamp of the following subbuffers.
 */
static inline
void lib_ring_buffer_check_deliver(const struct lttng_ust_ring_buffer_config *config,
				   struct lttng_ust_ring_buffer *buf,
			           struct lttng_ust_ring_buffer_channel *chan,
			           unsigned long offset,
				   unsigned long commit_count,
			           unsigned long idx,
				   struct lttng_ust_shm_handle *handle,
				   const struct lttng_ust_ring_buffer_ctx *ctx)
{
	unsigned long old_commit_count = commit_count
					 - chan->backend.subbuf_size;

	/* Check if all commits have been done */
	if (caa_unlikely((buf_trunc(offset, chan) >> chan->backend.num_subbuf_order)
		     - (old_commit_count & chan->commit_count_mask) == 0))
		lib_ring_buffer_check_deliver_slow(config, buf, chan, offset,
			commit_count, idx, handle, ctx);
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
void lib_ring_buffer_write_commit_counter(
		const struct lttng_ust_ring_buffer_config *config,
		struct lttng_ust_ring_buffer *buf __attribute__((unused)),
		struct lttng_ust_ring_buffer_channel *chan,
		unsigned long buf_offset,
		unsigned long commit_count,
		struct lttng_ust_shm_handle *handle __attribute__((unused)),
		struct commit_counters_hot *cc_hot)
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

	commit_seq_old = v_read(config, &cc_hot->seq);

	/*
	 * The sequence count can be equal to the commit count (== 0), if and only if,
	 * there is no padding in the sub-buffer.
	 */
	if (caa_likely((long) (commit_seq_old - commit_count) > 0))
		abort();

	v_set(config, &cc_hot->seq, commit_count);
}

/**
 * lib_ring_buffer_try_take_subbuf_ownership - Try to take the ownership of a
 * sub-buffer.
 *
 * @config: ring buffer instance configuration.
 * @chan: ring buffer channel instance.
 * @buf: ring buffer instance.
 * @subbuf_index: index of subbufer in @buf to take ownership of.
 * @handle: share memory handle.
 *
 * On success, the ownership of the subbuffer at @subbuf_index in @buf is now
 * this process and return 0.
 */
static inline
int lib_ring_buffer_try_take_subbuf_ownership(const struct lttng_ust_ring_buffer_config *config,
					struct lttng_ust_ring_buffer_channel *chan,
					struct lttng_ust_ring_buffer *buf,
					unsigned long subbuf_idx,
					struct lttng_ust_shm_handle *handle)
{
	struct commit_counters_hot *cc_hot;
	union v_atomic *owner;
	long new_owner, old_owner;

	cc_hot = shmp_index(handle, buf->commit_hot, subbuf_idx);

	if (caa_unlikely(!cc_hot))
		return -1;

	new_owner = chan->u.s.owner_id;
	owner = &cc_hot->owner;

	old_owner = v_cmpxchg(config, owner, LTTNG_UST_ABI_OWNER_ID_UNSET, new_owner);

	if (caa_unlikely(old_owner != LTTNG_UST_ABI_OWNER_ID_UNSET)) {
		return -1;
	}

	return 0;
}

static inline
int lib_ring_buffer_release_subbuf_ownership(const struct lttng_ust_ring_buffer_config *config,
					struct lttng_ust_ring_buffer *buf,
					unsigned long subbuf_idx,
					struct lttng_ust_shm_handle *handle)
{
	struct commit_counters_hot *cc_hot;

	cc_hot = shmp_index(handle, buf->commit_hot, subbuf_idx);

	if (caa_unlikely(!cc_hot))
		return -1;

	/*
	 * The sequential consistency MO acts as a store-release
	 * semi-permeable barrier to order stores performed with
	 * ownership held before releasing the ownership.
	 *
	 * The sequential consistency MO is also needed to order the
	 * store to the sub-buffer owner (releasing ownership) before
	 * the following sequential consistency load of `buf->offset`.
	 *
	 * This pairs with the sequence of cmpxchg to `buf->offset`
	 * in lib_ring_buffer_switch_slow() followed by a cmpxchg to
	 * sub-buffer owner lib_ring_buffer_try_clear_lazy_padding().
	 * Both of those cmpxchg are sequential consistency on success.
	 *
	 * These sequences of (store-X/load-Y, store-Y/load-X) form a
	 * Dekker memory ordering. This guarantees that the lazy padding
	 * is performed as soon as the ownership is released without
	 * relying on buffer stall recovery.
	 */
	v_store(config, &cc_hot->owner, LTTNG_UST_ABI_OWNER_ID_UNSET, CMM_SEQ_CST);

	return 0;
}

extern void lib_ring_buffer_lazy_padding_as_owner_slow(const struct lttng_ust_ring_buffer_config *config,
						struct lttng_ust_ring_buffer_channel *chan,
						struct lttng_ust_ring_buffer *buf,
						unsigned long subbuf_idx,
						struct lttng_ust_shm_handle *handle,
						const struct lttng_ust_ring_buffer_ctx *ctx,
						unsigned long hot);

static inline
void lib_ring_buffer_lazy_padding_as_owner(const struct lttng_ust_ring_buffer_config *config,
					struct lttng_ust_ring_buffer_channel *chan,
					struct lttng_ust_ring_buffer *buf,
					unsigned long subbuf_idx,
					struct lttng_ust_shm_handle *handle,
					const struct lttng_ust_ring_buffer_ctx *ctx,
					unsigned long *sampled_reserve)
{
	struct commit_counters_hot *cc_hot;
	long hot, reserve;

	reserve = v_read(config, &buf->offset);
	if (sampled_reserve)
		*sampled_reserve = reserve;

	/*
	 * Reserve position has not moved during commit.
	 */
	if (reserve == ctx->priv->reserve_then) {
		return;
	}

	cc_hot = shmp_index(handle, buf->commit_hot, subbuf_idx);

	if (caa_unlikely(!cc_hot))
		return;

	/*
	 * It is okay to read the hot value out of order and not atomically
	 * because it is guaranteed that only the owner of the sub-buffer calls
	 * this function.
	 */
	hot = cc_hot->cc.v;


	/*
	 * At this point, a lazy padding is only required if the hot commit
	 * counter is not fully balanced with respect to the reserve position.
	 */
	if (reserve - (long)subbuf_minimum_reserve(hot, subbuf_idx, chan) > 0) {
		lib_ring_buffer_lazy_padding_as_owner_slow(config, chan, buf, subbuf_idx,
						handle, ctx, hot);
	}
}

static inline
void lib_ring_buffer_clear_owner_lazy_padding(const struct lttng_ust_ring_buffer_config *config,
					struct lttng_ust_ring_buffer_channel *chan,
					struct lttng_ust_ring_buffer *buf,
					unsigned long subbuf_idx,
					struct lttng_ust_shm_handle *handle,
					const struct lttng_ust_ring_buffer_ctx *ctx)
{
	unsigned long sampled_reserve;

	lib_ring_buffer_lazy_padding_as_owner(config, chan, buf, subbuf_idx, handle, ctx, &sampled_reserve);
	TESTPOINT("lib_ring_buffer_clear_owner_lazy_padding_before_ownership_release");
	(void) lib_ring_buffer_release_subbuf_ownership(config, buf, subbuf_idx, handle);

	/*
	 * Re-validate the sampled reserve position after releasing
	 * ownership. This takes care of situations where a concurrent producer
	 * moves the reserve position between our sampled_reserve snapshot and
	 * release of the subbuffer ownership.
	 *
	 * When this is detected, try to take ownership again to do the lazy
	 * padding. If the ownership is already taken by a concurrent producer,
	 * it means it moved the reserve position immediately *after* we have
	 * released ownership. There is no lazy padding to handle in that
	 * scenario.
	 *
	 * Refer to the comment within lib_ring_buffer_release_subbuf_ownership()
	 * for explanation of the seq-cst memory ordering.
	 */
	if (sampled_reserve != v_load(config, &buf->offset, CMM_SEQ_CST)) {
		TESTPOINT("lib_ring_buffer_clear_owner_lazy_padding_before_take_ownership");
		if (lib_ring_buffer_try_take_subbuf_ownership(config, chan, buf, subbuf_idx, handle) == 0) {
			lib_ring_buffer_lazy_padding_as_owner(config, chan, buf, subbuf_idx, handle, ctx, NULL);
			(void) lib_ring_buffer_release_subbuf_ownership(config, buf, subbuf_idx, handle);
		}
	}
}

static inline
void lib_ring_buffer_try_clear_lazy_padding(const struct lttng_ust_ring_buffer_config *config,
					struct lttng_ust_ring_buffer_channel *chan,
					struct lttng_ust_ring_buffer *buf,
					unsigned long subbuf_idx,
					struct lttng_ust_shm_handle *handle,
					const struct lttng_ust_ring_buffer_ctx *ctx)
{
	if (lib_ring_buffer_try_take_subbuf_ownership(config, chan, buf, subbuf_idx, handle) == 0)
		lib_ring_buffer_clear_owner_lazy_padding(config, chan, buf, subbuf_idx, handle, ctx);
}

extern int lib_ring_buffer_create(struct lttng_ust_ring_buffer *buf,
				  struct channel_backend *chanb, int cpu,
				  struct lttng_ust_shm_handle *handle,
				  struct shm_object *shmobj,
				  bool preallocate_backing)
	__attribute__((visibility("hidden")));

extern void lib_ring_buffer_free(struct lttng_ust_ring_buffer *buf,
				 struct lttng_ust_shm_handle *handle)
	__attribute__((visibility("hidden")));

/* Keep track of trap nesting inside ring buffer code */
extern DECLARE_URCU_TLS(unsigned int, lib_ring_buffer_nesting)
	__attribute__((visibility("hidden")));

#endif /* _LTTNG_RING_BUFFER_FRONTEND_INTERNAL_H */
