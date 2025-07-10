/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2005-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Ring buffer backend (internal helpers).
 */

#ifndef _LTTNG_RING_BUFFER_BACKEND_INTERNAL_H
#define _LTTNG_RING_BUFFER_BACKEND_INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <urcu/compiler.h>

#include <lttng/ust-ringbuffer-context.h>
#include "ringbuffer-config.h"
#include "backend_types.h"
#include "frontend_types.h"
#include "shm.h"

/* Ring buffer backend API presented to the frontend */

/* Ring buffer and channel backend create/free */

int lib_ring_buffer_backend_create(struct lttng_ust_ring_buffer_backend *bufb,
				   struct channel_backend *chan,
				   int cpu,
				   struct lttng_ust_shm_handle *handle,
				   struct shm_object *shmobj,
				   bool populate)
	__attribute__((visibility("hidden")));

void channel_backend_unregister_notifiers(struct channel_backend *chanb)
	__attribute__((visibility("hidden")));

void lib_ring_buffer_backend_free(struct lttng_ust_ring_buffer_backend *bufb)
	__attribute__((visibility("hidden")));

int channel_backend_init(struct channel_backend *chanb,
			 const char *name,
			 const struct lttng_ust_ring_buffer_config *config,
			 size_t subbuf_size,
			 size_t num_subbuf, struct lttng_ust_shm_handle *handle,
			 const int *stream_fds,
			 bool preallocate_backing)
	__attribute__((visibility("hidden")));

void channel_backend_free(struct channel_backend *chanb,
			  struct lttng_ust_shm_handle *handle)
	__attribute__((visibility("hidden")));

void lib_ring_buffer_backend_reset(struct lttng_ust_ring_buffer_backend *bufb,
				   struct lttng_ust_shm_handle *handle)
	__attribute__((visibility("hidden")));

void channel_backend_reset(struct channel_backend *chanb)
	__attribute__((visibility("hidden")));

int lib_ring_buffer_backend_init(void)
	__attribute__((visibility("hidden")));

void lib_ring_buffer_backend_exit(void)
	__attribute__((visibility("hidden")));

extern void _lib_ring_buffer_write(struct lttng_ust_ring_buffer_backend *bufb,
				   size_t offset, const void *src, size_t len,
				   ssize_t pagecpy)
	__attribute__((visibility("hidden")));

/*
 * Subbuffer ID bits for overwrite mode. Need to fit within a single word to be
 * exchanged atomically.
 *
 * Top half word, except lowest bit, belongs to "offset", which is used to keep
 * to count the produced buffers.  For overwrite mode, this provides the
 * consumer with the capacity to read subbuffers in order, handling the
 * situation where producers would write up to 2^15 buffers (or 2^31 for 64-bit
 * systems) concurrently with a single execution of get_subbuf (between offset
 * sampling and subbuffer ID exchange).
 */

#define HALF_ULONG_BITS		(CAA_BITS_PER_LONG >> 1)

#define SB_ID_OFFSET_SHIFT	(HALF_ULONG_BITS + 1)
#define SB_ID_OFFSET_COUNT	(1UL << SB_ID_OFFSET_SHIFT)
#define SB_ID_OFFSET_MASK	(~(SB_ID_OFFSET_COUNT - 1))
/*
 * Lowest bit of top word half belongs to noref. Used only for overwrite mode.
 */
#define SB_ID_NOREF_SHIFT	(SB_ID_OFFSET_SHIFT - 1)
#define SB_ID_NOREF_COUNT	(1UL << SB_ID_NOREF_SHIFT)
#define SB_ID_NOREF_MASK	SB_ID_NOREF_COUNT
/*
 * In overwrite mode: lowest half of word is used for index.
 * Limit of 2^16 subbuffers per buffer on 32-bit, 2^32 on 64-bit.
 * In producer-consumer mode: whole word used for index.
 */
#define SB_ID_INDEX_SHIFT	0
#define SB_ID_INDEX_COUNT	(1UL << SB_ID_INDEX_SHIFT)
#define SB_ID_INDEX_MASK	(SB_ID_NOREF_COUNT - 1)

/*
 * Construct the subbuffer id from offset, index and noref. Use only the index
 * for producer-consumer mode (offset and noref are only used in overwrite
 * mode).
 */
static inline
unsigned long subbuffer_id(const struct lttng_ust_ring_buffer_config *config __attribute__((unused)),
			   unsigned long offset, unsigned long noref,
			   unsigned long index)
{
	return (offset << SB_ID_OFFSET_SHIFT) | (noref << SB_ID_NOREF_SHIFT) | index;
}

/*
 * Compare offset with the offset contained within id. Return 1 if the offset
 * bits are identical, else 0.
 */
static inline
int subbuffer_id_compare_offset(
		const struct lttng_ust_ring_buffer_config *config __attribute__((unused)),
		unsigned long id, unsigned long offset)
{
	return (id & SB_ID_OFFSET_MASK) == (offset << SB_ID_OFFSET_SHIFT);
}

static inline
unsigned long subbuffer_id_get_index(const struct lttng_ust_ring_buffer_config *config __attribute__((unused)),
				     unsigned long id)
{
	return id & SB_ID_INDEX_MASK;
}

static inline
unsigned long subbuffer_id_is_noref(const struct lttng_ust_ring_buffer_config *config __attribute__((unused)),
				    unsigned long id)
{
	return !!(id & SB_ID_NOREF_MASK);
}

/*
 * Only used by reader on subbuffer ID it has exclusive access to. No volatile
 * needed.
 */
static inline
void subbuffer_id_set_noref(const struct lttng_ust_ring_buffer_config *config __attribute__((unused)),
			    unsigned long *id)
{
	*id |= SB_ID_NOREF_MASK;
}

static inline
void subbuffer_id_set_noref_offset(const struct lttng_ust_ring_buffer_config *config __attribute__((unused)),
				   unsigned long *id, unsigned long offset)
{
	unsigned long tmp;

	tmp = *id;
	tmp &= ~SB_ID_OFFSET_MASK;
	tmp |= offset << SB_ID_OFFSET_SHIFT;
	tmp |= SB_ID_NOREF_MASK;
	/* Volatile store, read concurrently by readers. */
	CMM_ACCESS_ONCE(*id) = tmp;
}

/* No volatile access, since already used locally */
static inline
void subbuffer_id_clear_noref(const struct lttng_ust_ring_buffer_config *config __attribute__((unused)),
			      unsigned long *id)
{
	*id &= ~SB_ID_NOREF_MASK;
}

/*
 * For overwrite mode, cap the number of subbuffers per buffer to:
 * 2^16 on 32-bit architectures
 * 2^32 on 64-bit architectures
 * This is required to fit in the index part of the ID. Return 0 on success,
 * -EPERM on failure.
 */
static inline
int subbuffer_id_check_index(const struct lttng_ust_ring_buffer_config *config __attribute__((unused)),
			     unsigned long num_subbuf)
{
	return (num_subbuf > (1UL << HALF_ULONG_BITS)) ? -EPERM : 0;
}

static inline
int lib_ring_buffer_backend_get_pages(const struct lttng_ust_ring_buffer_config *config,
			const struct lttng_ust_ring_buffer_ctx *ctx,
			struct lttng_ust_ring_buffer_backend_pages **backend_pages)
{
	struct lttng_ust_ring_buffer_ctx_private *ctx_private = ctx->priv;
	struct lttng_ust_ring_buffer_backend *bufb = &ctx_private->buf->backend;
	struct channel_backend *chanb = &ctx_private->chan->backend;
	struct lttng_ust_shm_handle *handle = ctx_private->chan->handle;
	size_t sbidx;
	size_t offset = ctx_private->buf_offset;
	struct lttng_ust_ring_buffer_backend_subbuffer *wsb;
	struct lttng_ust_ring_buffer_backend_pages_shmp *rpages;
	unsigned long sb_bindex, id;
	struct lttng_ust_ring_buffer_backend_pages *_backend_pages;

	offset &= chanb->buf_size - 1;
	sbidx = offset >> chanb->subbuf_size_order;
	wsb = shmp_index(handle, bufb->buf_wsb, sbidx);
	if (caa_unlikely(!wsb))
		return -1;
	id = wsb->id;
	sb_bindex = subbuffer_id_get_index(config, id);
	rpages = shmp_index(handle, bufb->array, sb_bindex);
	if (caa_unlikely(!rpages))
		return -1;
	CHAN_WARN_ON(ctx_private->chan,
		     subbuffer_id_is_noref(config, id));
	_backend_pages = shmp(handle, rpages->shmp);
	if (caa_unlikely(!_backend_pages))
		return -1;
	*backend_pages = _backend_pages;
	return 0;
}

/* Get backend pages from cache. */
static inline
struct lttng_ust_ring_buffer_backend_pages *
	lib_ring_buffer_get_backend_pages_from_ctx(
		const struct lttng_ust_ring_buffer_config *config __attribute__((unused)),
		const struct lttng_ust_ring_buffer_ctx *ctx)
{
	return ctx->priv->backend_pages;
}

/*
 * The ring buffer can count events recorded and overwritten per buffer,
 * but it is disabled by default due to its performance overhead.
 */
#ifdef LTTNG_RING_BUFFER_COUNT_EVENTS
static inline
void subbuffer_count_record(const struct lttng_ust_ring_buffer_config *config,
			    const struct lttng_ust_ring_buffer_ctx *ctx)
{
	struct lttng_ust_ring_buffer_backend_pages *backend_pages;

	backend_pages = lib_ring_buffer_get_backend_pages_from_ctx(config, ctx);
	if (caa_unlikely(!backend_pages)) {
		if (lib_ring_buffer_backend_get_pages(config, ctx, &backend_pages))
			return;
	}
	v_inc(config, &backend_pages->records_commit);
}
#else /* LTTNG_RING_BUFFER_COUNT_EVENTS */
static inline
void subbuffer_count_record(const struct lttng_ust_ring_buffer_config *config __attribute__((unused)),
		const struct lttng_ust_ring_buffer_ctx *ctx __attribute__((unused)))
{
}
#endif /* #else LTTNG_RING_BUFFER_COUNT_EVENTS */

/*
 * Reader has exclusive subbuffer access for record consumption. No need to
 * perform the decrement atomically.
 */
static inline
void subbuffer_consume_record(const struct lttng_ust_ring_buffer_config *config,
			      struct lttng_ust_ring_buffer_backend *bufb,
			      struct lttng_ust_shm_handle *handle)
{
	unsigned long sb_bindex;
	struct lttng_ust_ring_buffer_channel *chan;
	struct lttng_ust_ring_buffer_backend_pages_shmp *pages_shmp;
	struct lttng_ust_ring_buffer_backend_pages *backend_pages;

	sb_bindex = subbuffer_id_get_index(config, bufb->buf_rsb.id);
	chan = shmp(handle, bufb->chan);
	if (!chan)
		return;
	pages_shmp = shmp_index(handle, bufb->array, sb_bindex);
	if (!pages_shmp)
		return;
	backend_pages = shmp(handle, pages_shmp->shmp);
	if (!backend_pages)
		return;
	CHAN_WARN_ON(chan, !v_read(config, &backend_pages->records_unread));
	/* Non-atomic decrement protected by exclusive subbuffer access */
	_v_dec(config, &backend_pages->records_unread);
	v_inc(config, &bufb->records_read);
}

static inline
unsigned long subbuffer_get_records_count(
				const struct lttng_ust_ring_buffer_config *config,
				struct lttng_ust_ring_buffer_backend *bufb,
				unsigned long idx,
				struct lttng_ust_shm_handle *handle)
{
	unsigned long sb_bindex;
	struct lttng_ust_ring_buffer_backend_subbuffer *wsb;
	struct lttng_ust_ring_buffer_backend_pages_shmp *rpages;
	struct lttng_ust_ring_buffer_backend_pages *backend_pages;

	wsb = shmp_index(handle, bufb->buf_wsb, idx);
	if (!wsb)
		return 0;
	sb_bindex = subbuffer_id_get_index(config, wsb->id);
	rpages = shmp_index(handle, bufb->array, sb_bindex);
	if (!rpages)
		return 0;
	backend_pages = shmp(handle, rpages->shmp);
	if (!backend_pages)
		return 0;
	return v_read(config, &backend_pages->records_commit);
}

/*
 * Must be executed at subbuffer delivery when the writer has _exclusive_
 * subbuffer access. See lib_ring_buffer_check_deliver() for details.
 * lib_ring_buffer_get_records_count() must be called to get the records
 * count before this function, because it resets the records_commit
 * count.
 */
static inline
unsigned long subbuffer_count_records_overrun(
				const struct lttng_ust_ring_buffer_config *config,
				struct lttng_ust_ring_buffer_backend *bufb,
				unsigned long idx,
				struct lttng_ust_shm_handle *handle)
{
	unsigned long overruns, sb_bindex;
	struct lttng_ust_ring_buffer_backend_subbuffer *wsb;
	struct lttng_ust_ring_buffer_backend_pages_shmp *rpages;
	struct lttng_ust_ring_buffer_backend_pages *backend_pages;

	wsb = shmp_index(handle, bufb->buf_wsb, idx);
	if (!wsb)
		return 0;
	sb_bindex = subbuffer_id_get_index(config, wsb->id);
	rpages = shmp_index(handle, bufb->array, sb_bindex);
	if (!rpages)
		return 0;
	backend_pages = shmp(handle, rpages->shmp);
	if (!backend_pages)
		return 0;
	overruns = v_read(config, &backend_pages->records_unread);
	v_set(config, &backend_pages->records_unread,
	      v_read(config, &backend_pages->records_commit));
	v_set(config, &backend_pages->records_commit, 0);

	return overruns;
}

static inline
void subbuffer_set_data_size(const struct lttng_ust_ring_buffer_config *config,
			     struct lttng_ust_ring_buffer_backend *bufb,
			     unsigned long idx,
			     unsigned long data_size,
			     struct lttng_ust_shm_handle *handle)
{
	unsigned long sb_bindex;
	struct lttng_ust_ring_buffer_backend_subbuffer *wsb;
	struct lttng_ust_ring_buffer_backend_pages_shmp *rpages;
	struct lttng_ust_ring_buffer_backend_pages *backend_pages;

	wsb = shmp_index(handle, bufb->buf_wsb, idx);
	if (!wsb)
		return;
	sb_bindex = subbuffer_id_get_index(config, wsb->id);
	rpages = shmp_index(handle, bufb->array, sb_bindex);
	if (!rpages)
		return;
	backend_pages = shmp(handle, rpages->shmp);
	if (!backend_pages)
		return;
	backend_pages->data_size = data_size;
}

static inline
unsigned long subbuffer_get_read_data_size(
				const struct lttng_ust_ring_buffer_config *config,
				struct lttng_ust_ring_buffer_backend *bufb,
				struct lttng_ust_shm_handle *handle)
{
	unsigned long sb_bindex;
	struct lttng_ust_ring_buffer_backend_pages_shmp *pages_shmp;
	struct lttng_ust_ring_buffer_backend_pages *backend_pages;

	sb_bindex = subbuffer_id_get_index(config, bufb->buf_rsb.id);
	pages_shmp = shmp_index(handle, bufb->array, sb_bindex);
	if (!pages_shmp)
		return 0;
	backend_pages = shmp(handle, pages_shmp->shmp);
	if (!backend_pages)
		return 0;
	return backend_pages->data_size;
}

static inline
unsigned long subbuffer_get_data_size(
				const struct lttng_ust_ring_buffer_config *config,
				struct lttng_ust_ring_buffer_backend *bufb,
				unsigned long idx,
				struct lttng_ust_shm_handle *handle)
{
	unsigned long sb_bindex;
	struct lttng_ust_ring_buffer_backend_subbuffer *wsb;
	struct lttng_ust_ring_buffer_backend_pages_shmp *rpages;
	struct lttng_ust_ring_buffer_backend_pages *backend_pages;

	wsb = shmp_index(handle, bufb->buf_wsb, idx);
	if (!wsb)
		return 0;
	sb_bindex = subbuffer_id_get_index(config, wsb->id);
	rpages = shmp_index(handle, bufb->array, sb_bindex);
	if (!rpages)
		return 0;
	backend_pages = shmp(handle, rpages->shmp);
	if (!backend_pages)
		return 0;
	return backend_pages->data_size;
}

/*
 * Reader the packet counter of the sub-buffer at `idx`, given the current cold
 * commit counter `current_commit_cold`.
 *
 * On error, return ~0ULL.
 */
static inline
uint64_t subbuffer_load_packet_count(
		const struct lttng_ust_ring_buffer_channel *chan,
		struct lttng_ust_ring_buffer *buf,
		struct lttng_ust_shm_handle *handle,
		unsigned long current_commit_cold,
		unsigned long idx)
{
	struct lttng_ust_ring_buffer_backend_counts *counts;
	size_t seq_idx;

	counts = shmp_index(handle, buf->backend.buf_cnt, idx);
	if (!counts)
		return ~0ULL;

	seq_idx = (current_commit_cold >> chan->backend.subbuf_size_order) & 1;

	return counts->seq_cnt[seq_idx];
}

/*
 * Increment the packet count of sub-buffer at index `idx`, given the future
 * value the cold commit counter `next_commit_cold`. Note that this only
 * prepares the future slot and won't be observable by readers until the cold
 * commit counter is moved to `next_commit_cold`.
 *
 * The sequence counter allows for atomic transaction that will be visible to
 * reader once the cold commit counter is `next_commit_cold`.
 *
 * This works by preparing the value that will become the true value once the
 * cold commit counter reached `next_commit_cold` by incrementing the value in
 * the current slot and storing it in the next slot.
 *
 * Thus, the increment has the following properties:
 *
 *   - Mutually exclusive with respect to readers and writers
 *
 *   - Restartable by a fixup if the producer crashed before storing the
 *     `next_commit_cold` into the cold commit counter
 */
static inline
void subbuffer_inc_packet_count(
		const struct lttng_ust_ring_buffer_channel *chan,
		struct lttng_ust_ring_buffer *buf,
		struct lttng_ust_shm_handle *handle,
		unsigned long next_commit_cold,
		unsigned long idx)
{
	struct lttng_ust_ring_buffer_backend_counts *counts;
	size_t seq_idx;

	counts = shmp_index(handle, buf->backend.buf_cnt, idx);
	if (!counts)
		return;

	seq_idx = (next_commit_cold >> chan->backend.subbuf_size_order) & 1;

	counts->seq_cnt[seq_idx] = counts->seq_cnt[1 - seq_idx] + 1;
}

/**
 * lib_ring_buffer_clear_noref - Clear the noref subbuffer flag, called by
 *                               writer.
 */
static inline
void lib_ring_buffer_clear_noref(const struct lttng_ust_ring_buffer_config *config,
				 struct lttng_ust_ring_buffer_backend *bufb,
				 unsigned long idx,
				 struct lttng_ust_shm_handle *handle)
{
	unsigned long id, new_id;
	struct lttng_ust_ring_buffer_backend_subbuffer *wsb;

	/*
	 * Performing a volatile access to read the sb_pages, because we want to
	 * read a coherent version of the pointer and the associated noref flag.
	 */
	wsb = shmp_index(handle, bufb->buf_wsb, idx);
	if (!wsb)
		return;
	id = CMM_ACCESS_ONCE(wsb->id);
	for (;;) {
		/* This check is called on the fast path for each record. */
		if (caa_likely(!subbuffer_id_is_noref(config, id))) {
			/*
			 * Store after load dependency ordering the writes to
			 * the subbuffer after load and test of the noref flag
			 * matches the memory barrier implied by the cmpxchg()
			 * in update_read_sb_index().
			 */
			return;	/* Already writing to this buffer */
		}
		new_id = id;
		subbuffer_id_clear_noref(config, &new_id);
		new_id = uatomic_cmpxchg(&wsb->id, id, new_id);
		if (caa_likely(new_id == id))
			break;
		id = new_id;
	}
}

/**
 * lib_ring_buffer_set_noref_offset - Set the noref subbuffer flag and offset,
 *                                    called by writer.
 */
static inline
void lib_ring_buffer_set_noref_offset(const struct lttng_ust_ring_buffer_config *config,
				      struct lttng_ust_ring_buffer_backend *bufb,
				      unsigned long idx, unsigned long offset,
				      struct lttng_ust_shm_handle *handle)
{
	struct lttng_ust_ring_buffer_backend_subbuffer *wsb;
	struct lttng_ust_ring_buffer_channel *chan;

	wsb = shmp_index(handle, bufb->buf_wsb, idx);
	if (!wsb)
		return;
	/*
	 * Because ring_buffer_set_noref() is only called by a single thread
	 * (the one which updated the cc_sb value), there are no concurrent
	 * updates to take care of: other writers have not updated cc_sb, so
	 * they cannot set the noref flag, and concurrent readers cannot modify
	 * the pointer because the noref flag is not set yet.
	 * The smp_wmb() in ring_buffer_commit() takes care of ordering writes
	 * to the subbuffer before this set noref operation.
	 * subbuffer_set_noref() uses a volatile store to deal with concurrent
	 * readers of the noref flag.
	 */
	chan = shmp(handle, bufb->chan);
	if (!chan)
		return;
	CHAN_WARN_ON(chan, subbuffer_id_is_noref(config, wsb->id));
	/*
	 * Memory barrier that ensures counter stores are ordered before set
	 * noref and offset.
	 */
	cmm_smp_mb();
	subbuffer_id_set_noref_offset(config, &wsb->id, offset);
}

/**
 * update_read_sb_index - Read-side subbuffer index update.
 */
static inline
int update_read_sb_index(const struct lttng_ust_ring_buffer_config *config,
			 struct lttng_ust_ring_buffer_backend *bufb,
			 struct channel_backend *chanb __attribute__((unused)),
			 unsigned long consumed_idx,
			 unsigned long consumed_count,
			 struct lttng_ust_shm_handle *handle)
{
	struct lttng_ust_ring_buffer_backend_subbuffer *wsb;
	struct lttng_ust_ring_buffer_channel *chan;
	unsigned long old_id, new_id;

	wsb = shmp_index(handle, bufb->buf_wsb, consumed_idx);
	if (caa_unlikely(!wsb))
		return -EPERM;

	/*
	 * Exchange the target writer subbuffer with our own unused
	 * subbuffer. No need to use CMM_ACCESS_ONCE() here to read the
	 * old_wpage, because the value read will be confirmed by the
	 * following cmpxchg().
	 */
	old_id = wsb->id;
	if (caa_unlikely(!subbuffer_id_is_noref(config, old_id)))
		return -EAGAIN;
	/*
	 * Make sure the offset count we are expecting matches the one
	 * indicated by the writer.
	 */
	if (caa_unlikely(!subbuffer_id_compare_offset(config, old_id,
						  consumed_count)))
		return -EAGAIN;
	chan = shmp(handle, bufb->chan);
	if (caa_unlikely(!chan))
		return -EPERM;
	CHAN_WARN_ON(chan, !subbuffer_id_is_noref(config, bufb->buf_rsb.id));
	subbuffer_id_set_noref_offset(config, &bufb->buf_rsb.id,
				      consumed_count);
	new_id = uatomic_cmpxchg(&wsb->id, old_id, bufb->buf_rsb.id);
	if (caa_unlikely(old_id != new_id))
		return -EAGAIN;
	bufb->buf_rsb.id = new_id;
	return 0;
}

#ifndef inline_memcpy
#define inline_memcpy(dest, src, n)	memcpy(dest, src, n)
#endif

#define LOAD_UNALIGNED_INT(type, p) \
	({ \
		struct packed_struct { type __v; } __attribute__((packed)); \
		(((const struct packed_struct *) (p))->__v); \
	})

#define STORE_UNALIGNED_INT(type, p, v)	\
	do { \
		struct packed_struct { type __v; } __attribute__((packed)); \
		((struct packed_struct *) (p))->__v = (v); \
	} while (0)

/*
 * Copy from src into dest, assuming unaligned src and dest.
 */
static inline
void lttng_inline_memcpy(void *dest, const void *src,
		unsigned long len)
	__attribute__((always_inline));
static inline
void lttng_inline_memcpy(void *dest, const void *src,
		unsigned long len)
{
	switch (len) {
	case 1:
		*(uint8_t *) dest = *(const uint8_t *) src;
		break;
	case 2:
		STORE_UNALIGNED_INT(uint16_t, dest, LOAD_UNALIGNED_INT(uint16_t, src));
		break;
	case 4:
		STORE_UNALIGNED_INT(uint32_t, dest, LOAD_UNALIGNED_INT(uint32_t, src));
		break;
	case 8:
		STORE_UNALIGNED_INT(uint64_t, dest, LOAD_UNALIGNED_INT(uint64_t, src));
		break;
	default:
		inline_memcpy(dest, src, len);
	}
}

/*
 * Use the architecture-specific memcpy implementation for constant-sized
 * inputs, but rely on an inline memcpy for length statically unknown.
 * The function call to memcpy is just way too expensive for a fast path.
 */
#define lib_ring_buffer_do_copy(config, dest, src, len)		\
do {								\
	size_t __len = (len);					\
	if (__builtin_constant_p(len))				\
		memcpy(dest, src, __len);			\
	else							\
		lttng_inline_memcpy(dest, src, __len);		\
} while (0)

/*
 * write len bytes to dest with c
 */
static inline
void lib_ring_buffer_do_memset(char *dest, char c, unsigned long len)
{
	unsigned long i;

	for (i = 0; i < len; i++)
		dest[i] = c;
}

#endif /* _LTTNG_RING_BUFFER_BACKEND_INTERNAL_H */
