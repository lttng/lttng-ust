/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2005-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * See ring_buffer_frontend.c for more information on wait-free
 * algorithms.
 * See frontend.h for channel allocation and read-side API.
 */

#ifndef _LTTNG_RING_BUFFER_FRONTEND_API_H
#define _LTTNG_RING_BUFFER_FRONTEND_API_H

#include <stddef.h>

#include <urcu/compiler.h>

#include "common/getcpu.h"
#include "common/testpoint.h"
#include "frontend.h"

/**
 * lib_ring_buffer_nesting_inc - Ring buffer recursive use protection.
 *
 * The rint buffer buffer nesting count is a safety net to ensure tracer
 * client code will never trigger an endless recursion.
 * Returns a nesting level >= 0 on success, -EPERM on failure (nesting
 * count too high).
 *
 * __asm__ __volatile__ and "memory" clobber prevent the compiler from moving
 * instructions out of the ring buffer nesting count. This is required to ensure
 * that probe side-effects which can cause recursion (e.g. unforeseen traps,
 * divisions by 0, ...) are triggered within the incremented nesting count
 * section.
 */
static inline
int lib_ring_buffer_nesting_inc(
		const struct lttng_ust_ring_buffer_config *config __attribute__((unused)))
{
	int nesting;

	nesting = ++URCU_TLS(lib_ring_buffer_nesting);
	cmm_barrier();
	if (caa_unlikely(nesting >= LIB_RING_BUFFER_MAX_NESTING)) {
		WARN_ON_ONCE(1);
		URCU_TLS(lib_ring_buffer_nesting)--;
		return -EPERM;
	}
	return nesting - 1;
}

static inline
int lib_ring_buffer_nesting_count(
		const struct lttng_ust_ring_buffer_config *config __attribute__((unused)))
{
	return URCU_TLS(lib_ring_buffer_nesting);
}

static inline
void lib_ring_buffer_nesting_dec(
		const struct lttng_ust_ring_buffer_config *config __attribute__((unused)))
{
	cmm_barrier();
	URCU_TLS(lib_ring_buffer_nesting)--;		/* TLS */
}

/*
 * lib_ring_buffer_try_reserve is called by lib_ring_buffer_reserve(). It is not
 * part of the API per se.
 *
 * returns 0 if reserve ok, or 1 if the slow path must be taken.
 */
static inline
int lib_ring_buffer_try_reserve(const struct lttng_ust_ring_buffer_config *config,
				struct lttng_ust_ring_buffer_ctx *ctx,
				void *client_ctx,
				unsigned long *o_begin, unsigned long *o_end,
				unsigned long *o_old, size_t *before_hdr_pad)
{
	struct lttng_ust_ring_buffer_ctx_private *ctx_private = ctx->priv;
	struct lttng_ust_ring_buffer_channel *chan = ctx_private->chan;
	struct lttng_ust_ring_buffer *buf = ctx_private->buf;
	*o_begin = v_read(config, &buf->offset);
	*o_old = *o_begin;

	/*
	 * Offset must be read before the timestamp to guarantee the increasing
	 * timestamp in the subbufer.
	 */
	ctx_private->timestamp = lib_ring_buffer_clock_read(chan);
	if ((int64_t) ctx_private->timestamp == -EIO)
		return 1;

	/*
	 * Prefetch cacheline for read because we have to read the previous
	 * commit counter to increment it and commit seq value to compare it to
	 * the commit counter.
	 */
	//prefetch(&buf->commit_hot[subbuf_index(*o_begin, chan)]);

	if (last_timestamp_overflow(config, buf, ctx_private->timestamp))
		ctx_private->rflags |= RING_BUFFER_RFLAG_FULL_TIMESTAMP;

	if (caa_unlikely(subbuf_offset(*o_begin, chan) == 0))
		return 1;

	ctx_private->slot_size = record_header_size(config, chan, *o_begin,
					    before_hdr_pad, ctx, client_ctx);
	ctx_private->slot_size +=
		lttng_ust_ring_buffer_align(*o_begin + ctx_private->slot_size,
				      ctx->largest_align) + ctx->data_size;
	if (caa_unlikely((subbuf_offset(*o_begin, chan) + ctx_private->slot_size)
		     > chan->backend.subbuf_size))
		return 1;

	/*
	 * Record fits in the current buffer and we are not on a switch
	 * boundary. It's safe to write.
	 */
	*o_end = *o_begin + ctx_private->slot_size;

	if (caa_unlikely((subbuf_offset(*o_end, chan)) == 0))
		/*
		 * The offset_end will fall at the very beginning of the next
		 * subbuffer.
		 */
		return 1;

	/*
	 * Populate the records lost counters prior to an eventual lazy
	 * padding.
	 */
	ctx_private->records_lost_full = v_read(config, &buf->records_lost_full);
	ctx_private->records_lost_wrap = v_read(config, &buf->records_lost_wrap);
	ctx_private->records_lost_big = v_read(config, &buf->records_lost_big);

	return 0;
}

/**
 * lib_ring_buffer_reserve - Reserve space in a ring buffer.
 * @config: ring buffer instance configuration.
 * @ctx: ring buffer context. (input and output) Must be already initialized.
 *
 * Atomic wait-free slot reservation. The reserved space starts at the context
 * "pre_offset". Its length is "slot_size". The associated time-stamp is
 * "timestamp".
 *
 * Return :
 *  0 on success.
 * -EAGAIN if channel is disabled.
 * -ENOSPC if event size is too large for packet.
 * -ENOBUFS if there is currently not enough space in buffer for the event.
 * -EIO if data cannot be written into the buffer for any other reason.
 */

static inline
int lib_ring_buffer_reserve(const struct lttng_ust_ring_buffer_config *config,
			    struct lttng_ust_ring_buffer_ctx *ctx,
			    void *client_ctx)
{
	struct lttng_ust_ring_buffer_ctx_private *ctx_private = ctx->priv;
	struct lttng_ust_ring_buffer_channel *chan = ctx_private->chan;
	struct lttng_ust_shm_handle *handle = chan->handle;
	struct lttng_ust_ring_buffer *buf;
	unsigned long o_begin, o_end, o_old;
	size_t before_hdr_pad = 0;

	if (caa_unlikely(uatomic_read(&chan->record_disabled)))
		return -EAGAIN;

	if (config->alloc == RING_BUFFER_ALLOC_PER_CPU) {
		ctx_private->reserve_cpu = lttng_ust_get_cpu();
		buf = shmp(handle, chan->backend.buf[ctx_private->reserve_cpu].shmp);
	} else {
		buf = shmp(handle, chan->backend.buf[0].shmp);
	}
	if (caa_unlikely(!buf))
		return -EIO;
	if (caa_unlikely(uatomic_read(&buf->record_disabled)))
		return -EAGAIN;
	ctx_private->buf = buf;

	/*
	 * Perform retryable operations.
	 */
	if (caa_unlikely(lib_ring_buffer_try_reserve(config, ctx, client_ctx, &o_begin,
						 &o_end, &o_old, &before_hdr_pad)))
		goto slow_path;

	/*
	 * Before taking the reservation, try to take the ownership.
	 */
	if (caa_unlikely(lib_ring_buffer_try_take_subbuf_ownership(
					config, chan, buf,
					subbuf_index(o_end - 1, chan),
					handle)))
		goto slow_path;

	/*
	 * Observable side-effect: Ownership of the sub-buffer is now taken.
	 * Other producers reservations are impacted.
	 */
	TESTPOINT("lib_ring_buffer_reserve_take_ownership_succeed");

	/*
	 * Try the fast reservation.  If failed, do the lazy padding of the
	 * sub-buffer before releasing ownership and going to the slowpath.
	 */
	if (caa_unlikely(v_cmpxchg(config, &buf->offset, o_old, o_end)
		     != o_old)) {
		lib_ring_buffer_clear_owner_lazy_padding(config,
							chan, buf,
							subbuf_index(o_end - 1, chan),
							handle,
							ctx);
		goto slow_path;
	}

	ctx->priv->reserve_then = o_end;

	/*
	 * Observable side-effect: Reservation offset has been incremented.
	 * Consumer's snapshots and other producers reservations are impacted.
	 */
	TESTPOINT("lib_ring_buffer_reserve_cmpxchg_succeed");

	/*
	 * Atomically update last_timestamp. This update races against concurrent
	 * atomic updates, but the race will always cause supplementary full
	 * timestamp record headers, never the opposite (missing a full
	 * timestamp record header when it would be needed).
	 */
	save_last_timestamp(config, chan, buf, ctx_private->timestamp);

	/*
	 * Push the reader if necessary
	 */
	lib_ring_buffer_reserve_push_reader(config, buf, chan, o_end - 1);

	TESTPOINT("lib_ring_buffer_reserve_after_push_reader");

	/*
	 * Clear noref flag for this subbuffer.
	 */
	lib_ring_buffer_clear_noref(config, &buf->backend,
				subbuf_index(o_end - 1, chan), handle);

	ctx_private->pre_offset = o_begin;
	ctx_private->buf_offset = o_begin + before_hdr_pad;
	return 0;
slow_path:
	return lib_ring_buffer_reserve_slow(ctx, client_ctx);
}

/**
 * lib_ring_buffer_switch - Perform a sub-buffer switch for a per-cpu buffer.
 * @config: ring buffer instance configuration.
 * @buf: buffer
 * @mode: buffer switch mode (SWITCH_ACTIVE or SWITCH_FLUSH)
 *
 * This operation is completely reentrant : can be called while tracing is
 * active with absolutely no lock held.
 *
 * Note, however, that as a v_cmpxchg is used for some atomic operations and
 * requires to be executed locally for per-CPU buffers, this function must be
 * called from the CPU which owns the buffer for a ACTIVE flush, with preemption
 * disabled, for RING_BUFFER_SYNC_PER_CPU configuration.
 */
static inline
void lib_ring_buffer_switch(
		const struct lttng_ust_ring_buffer_config *config __attribute__((unused)),
		struct lttng_ust_ring_buffer *buf, enum switch_mode mode,
		struct lttng_ust_shm_handle *handle)
{
	lib_ring_buffer_switch_slow(buf, mode, NULL, handle);
}

/* See ring_buffer_frontend_api.h for lib_ring_buffer_reserve(). */

/**
 * lib_ring_buffer_commit - Commit an record.
 * @config: ring buffer instance configuration.
 * @ctx: ring buffer context. (input arguments only)
 *
 * Atomic unordered slot commit. Increments the commit count in the
 * specified sub-buffer, and delivers it if necessary.
 */
static inline
void lib_ring_buffer_commit(const struct lttng_ust_ring_buffer_config *config,
			    const struct lttng_ust_ring_buffer_ctx *ctx)
{
	struct lttng_ust_ring_buffer_ctx_private *ctx_private = ctx->priv;
	struct lttng_ust_ring_buffer_channel *chan = ctx_private->chan;
	struct lttng_ust_shm_handle *handle = chan->handle;
	struct lttng_ust_ring_buffer *buf = ctx_private->buf;
	unsigned long offset_end = ctx_private->buf_offset;
	unsigned long endidx = subbuf_index(offset_end - 1, chan);
	unsigned long commit_count;
	struct commit_counters_hot *cc_hot = shmp_index(handle,
						buf->commit_hot, endidx);

	if (caa_unlikely(!cc_hot))
		return;

	/*
	 * Must count record before incrementing the commit count.
	 */
	subbuffer_count_record(config, ctx);

	/*
	 * Observable side-effect: The number of commited records is
	 * incremented.
	 *
	 * Consumer's snapshots are impacted.
	 *
	 * None-observable side-effect: The commit counter is not balanced with
	 * the reservation position.
	 */
	TESTPOINT("lib_ring_buffer_commit_after_record_count");

	commit_count = cc_hot->cc.a + ctx_private->slot_size;

	/*
	 * Only the owner of the sub-buffer can increment the hot commit
	 * counter.
	 * This needs to be atomically set with respect with readers.
	 * Store-release orders all writes to buffer before the commit
	 * count update that will determine that the subbuffer is full.
	 */
	v_store(config, &cc_hot->cc, commit_count, CMM_RELEASE);


	/*
	 * Observable side-effect: The hot commit counter of the sub-buffer is
	 * balanced for the last reservation in that sub-buffer.
	 *
	 * This impacts any producer trying to do a lazy-padding on the
	 * sub-buffer.
	 */
	TESTPOINT("lib_ring_buffer_commit_after_commit_count");

	lib_ring_buffer_check_deliver(config, buf, chan, offset_end - 1,
				      commit_count, endidx, handle, ctx);

	/*
	 * Update used size at each commit. It's needed only for extracting
	 * ring_buffer buffers from vmcore, after crash.
	 */
	lib_ring_buffer_write_commit_counter(config, buf, chan,
			offset_end, commit_count, handle, cc_hot);

	/*
	 * None-observable side-effect: Releasing the ownership of the
	 * sub-buffer.
	 *
	 * Producers will not get access to this sub-buffer until the ownership
	 * is released.
	 */
	TESTPOINT("lib_ring_buffer_commit_before_clear_owner");

	lib_ring_buffer_clear_owner_lazy_padding(config, chan, buf, endidx,
						handle, ctx);
}

/**
 * lib_ring_buffer_try_discard_reserve - Try discarding a record.
 * @config: ring buffer instance configuration.
 * @ctx: ring buffer context. (input arguments only)
 *
 * Only succeeds if no other record has been written after the record to
 * discard. If discard fails, the record must be committed to the buffer.
 *
 * Returns 0 upon success, -EPERM if the record cannot be discarded.
 */
static inline
int lib_ring_buffer_try_discard_reserve(const struct lttng_ust_ring_buffer_config *config,
					const struct lttng_ust_ring_buffer_ctx *ctx)
{
	struct lttng_ust_ring_buffer_ctx_private *ctx_private = ctx->priv;
	struct lttng_ust_ring_buffer *buf = ctx_private->buf;
	unsigned long end_offset = ctx_private->pre_offset + ctx_private->slot_size;

	/*
	 * We need to ensure that if the cmpxchg succeeds and discards the
	 * record, the next record will record a full timestamp, because it cannot
	 * rely on the last_timestamp associated with the discarded record to detect
	 * overflows. The only way to ensure this is to set the last_timestamp to 0
	 * (assuming no 64-bit timestamp overflow), which forces to write a 64-bit
	 * timestamp in the next record.
	 *
	 * Note: if discard fails, we must leave the timestamp in the record header.
	 * It is needed to keep track of timestamp overflows for the following
	 * records.
	 */
	save_last_timestamp(config, ctx_private->chan, buf, 0ULL);

	if (caa_likely(v_cmpxchg(config, &buf->offset, end_offset, ctx_private->pre_offset)
		   != end_offset))
		return -EPERM;
	else
		return 0;
}

static inline
void channel_record_disable(
		const struct lttng_ust_ring_buffer_config *config __attribute__((unused)),
		struct lttng_ust_ring_buffer_channel *chan)
{
	uatomic_inc(&chan->record_disabled);
}

static inline
void channel_record_enable(
		const struct lttng_ust_ring_buffer_config *config __attribute__((unused)),
		struct lttng_ust_ring_buffer_channel *chan)
{
	uatomic_dec(&chan->record_disabled);
}

static inline
void lib_ring_buffer_record_disable(
		const struct lttng_ust_ring_buffer_config *config __attribute__((unused)),
		struct lttng_ust_ring_buffer *buf)
{
	uatomic_inc(&buf->record_disabled);
}

static inline
void lib_ring_buffer_record_enable(
		const struct lttng_ust_ring_buffer_config *config __attribute__((unused)),
		struct lttng_ust_ring_buffer *buf)
{
	uatomic_dec(&buf->record_disabled);
}

#endif /* _LTTNG_RING_BUFFER_FRONTEND_API_H */
