/*
 * buffers.h
 *
 * Copyright (C) 2009 - Pierre-Marc Fournier (pierre-marc dot fournier at polymtl dot ca)
 * Copyright (C) 2008 - Mathieu Desnoyers (mathieu.desnoyers@polymtl.ca)
 *
 */

#ifndef _UST_BUFFERS_H
#define _UST_BUFFERS_H

#include <kcompat/kref.h>
#include <assert.h>
#include "channels.h"
#include "buffers.h"

/* Return the size of the minimum number of pages that can contain x. */
#define FIX_SIZE(x) ((((x) - 1) & PAGE_MASK) + PAGE_SIZE)

/*
 * BUFFER_TRUNC zeroes the subbuffer offset and the subbuffer number parts of
 * the offset, which leaves only the buffer number.
 */
#define BUFFER_TRUNC(offset, chan) \
	((offset) & (~((chan)->alloc_size-1)))
#define BUFFER_OFFSET(offset, chan) ((offset) & ((chan)->alloc_size - 1))
#define SUBBUF_OFFSET(offset, chan) ((offset) & ((chan)->subbuf_size - 1))
#define SUBBUF_ALIGN(offset, chan) \
	(((offset) + (chan)->subbuf_size) & (~((chan)->subbuf_size - 1)))
#define SUBBUF_TRUNC(offset, chan) \
	((offset) & (~((chan)->subbuf_size - 1)))
#define SUBBUF_INDEX(offset, chan) \
	(BUFFER_OFFSET((offset), chan) >> (chan)->subbuf_size_order)

/*
 * Tracks changes to rchan/rchan_buf structs
 */
#define UST_CHANNEL_VERSION		8

struct ust_buffer {
	/* First 32 bytes cache-hot cacheline */
	local_t offset;			/* Current offset in the buffer */
	local_t *commit_count;		/* Commit count per sub-buffer */
	atomic_long_t consumed;		/*
					 * Current offset in the buffer
					 * standard atomic access (shared)
					 */
	unsigned long last_tsc;		/*
					 * Last timestamp written in the buffer.
					 */
	/* End of first 32 bytes cacheline */
	atomic_long_t active_readers;	/*
					 * Active readers count
					 * standard atomic access (shared)
					 */
	local_t events_lost;
	local_t corrupted_subbuffers;
	/* one byte is written to this pipe when data is available, in order
           to wake the consumer */
	/* portability: Single byte writes must be as quick as possible. The kernel-side
	   buffer must be large enough so the writer doesn't block. From the pipe(7)
           man page: Since linux 2.6.11, the pipe capacity is 65536 bytes. */
	int data_ready_fd_write;
	/* the reading end of the pipe */
	int data_ready_fd_read;

	struct ust_channel *chan;
	struct kref kref;
	void *buf_data;
	size_t buf_size;
	int shmid;

	/* commit count per subbuffer; must be at end of struct */
	local_t commit_seq[0] ____cacheline_aligned;
} ____cacheline_aligned;

extern void _ust_buffers_write(struct ust_buffer *buf, size_t offset,
	const void *src, size_t len, ssize_t cpy);

/*
 * Return the address where a given offset is located.
 * Should be used to get the current subbuffer header pointer. Given we know
 * it's never on a page boundary, it's safe to write directly to this address,
 * as long as the write is never bigger than a page size.
 */
extern void *ust_buffers_offset_address(struct ust_buffer *buf,
	size_t offset);

/* FIXME: lttng has a version for systems with inefficient unaligned access */
static inline void ust_buffers_do_copy(void *dest, const void *src, size_t len)
{
	union {
		const void *src;
		const u8 *src8;
		const u16 *src16;
		const u32 *src32;
		const u64 *src64;
	} u = { .src = src };

	switch (len) {
	case 0:	break;
	case 1:	*(u8 *)dest = *u.src8;
		break;
	case 2:	*(u16 *)dest = *u.src16;
		break;
	case 4:	*(u32 *)dest = *u.src32;
		break;
	case 8:	*(u64 *)dest = *u.src64;
		break;
	default:
		memcpy(dest, src, len);
	}
}

/* FIXME: there is both a static inline and a '_' non static inline version ?? */
static inline int ust_buffers_write(struct ust_buffer *buf, size_t offset,
	const void *src, size_t len)
{
	size_t cpy;
	size_t buf_offset = BUFFER_OFFSET(offset, buf->chan);

	assert(buf_offset < buf->chan->subbuf_size*buf->chan->subbuf_cnt);

	cpy = min_t(size_t, len, buf->buf_size - buf_offset);
	ust_buffers_do_copy(buf->buf_data + buf_offset, src, cpy);
	
	if (unlikely(len != cpy))
		_ust_buffers_write(buf, buf_offset, src, len, cpy);
	return len;
}

int ust_buffers_channel_open(struct ust_channel *chan, size_t subbuf_size, size_t n_subbufs);
extern void ust_buffers_channel_close(struct ust_channel *chan);

extern int ust_buffers_do_get_subbuf(struct ust_buffer *buf, long *pconsumed_old);

extern int ust_buffers_do_put_subbuf(struct ust_buffer *buf, u32 uconsumed_old);

extern void init_ustrelay_transport(void);

/*static*/ /* inline */ notrace void ltt_commit_slot(
		struct ust_channel *channel,
		void **transport_data, long buf_offset,
		size_t data_size, size_t slot_size);

#endif /* _UST_BUFFERS_H */
