/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2008-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Ring buffer backend (types).
 */

#ifndef _LTTNG_RING_BUFFER_BACKEND_TYPES_H
#define _LTTNG_RING_BUFFER_BACKEND_TYPES_H

#include <limits.h>
#include <stdint.h>
#include "shm_internal.h"
#include "vatomic.h"

#define RB_BACKEND_PAGES_PADDING	16
struct lttng_ust_ring_buffer_backend_pages {
	unsigned long mmap_offset;	/* offset of the subbuffer in mmap */
	union v_atomic records_commit;	/* current records committed count */
	union v_atomic records_unread;	/* records to read */
	unsigned long data_size;	/* Amount of data to read from subbuf */
	DECLARE_SHMP(char, p);		/* Backing memory map */
	char padding[RB_BACKEND_PAGES_PADDING];
};

struct lttng_ust_ring_buffer_backend_subbuffer {
	/* Identifier for subbuf backend pages. Exchanged atomically. */
	unsigned long id;		/* backend subbuffer identifier */
};

struct lttng_ust_ring_buffer_backend_counts {
	/*
	 * Counter specific to the sub-buffer location within the ring buffer.
	 * The actual sequence number of the packet within the entire ring
	 * buffer can be derived from the formula nr_subbuffers * seq_cnt +
	 * subbuf_idx.
	 */
	uint64_t seq_cnt;               /* packet sequence number */
};

/*
 * Forward declaration of frontend-specific channel and ring_buffer.
 */
struct lttng_ust_ring_buffer_channel;
struct lttng_ust_ring_buffer;

struct lttng_ust_ring_buffer_backend_pages_shmp {
	DECLARE_SHMP(struct lttng_ust_ring_buffer_backend_pages, shmp);
};

#define RB_BACKEND_RING_BUFFER_PADDING		64
struct lttng_ust_ring_buffer_backend {
	/* Array of ring_buffer_backend_subbuffer for writer */
	DECLARE_SHMP(struct lttng_ust_ring_buffer_backend_subbuffer, buf_wsb);
	/* ring_buffer_backend_subbuffer for reader */
	struct lttng_ust_ring_buffer_backend_subbuffer buf_rsb;
	/* Array of lib_ring_buffer_backend_counts for the packet counter */
	DECLARE_SHMP(struct lttng_ust_ring_buffer_backend_counts, buf_cnt);
	/*
	 * Pointer array of backend pages, for whole buffer.
	 * Indexed by ring_buffer_backend_subbuffer identifier (id) index.
	 */
	DECLARE_SHMP(struct lttng_ust_ring_buffer_backend_pages_shmp, array);
	DECLARE_SHMP(char, memory_map);	/* memory mapping */

	DECLARE_SHMP(struct lttng_ust_ring_buffer_channel, chan);	/* Associated channel */
	int cpu;			/* This buffer's cpu. -1 if per-channel. */
	union v_atomic records_read;	/* Number of records read */
	unsigned int allocated:1;	/* is buffer allocated ? */
	char padding[RB_BACKEND_RING_BUFFER_PADDING];
};

struct lttng_ust_ring_buffer_shmp {
	DECLARE_SHMP(struct lttng_ust_ring_buffer, shmp); /* Channel per-cpu buffers */
};

#define RB_BACKEND_CHANNEL_PADDING	64
struct channel_backend {
	unsigned long buf_size;		/* Size of the buffer */
	unsigned long subbuf_size;	/* Sub-buffer size */
	unsigned int subbuf_size_order;	/* Order of sub-buffer size */
	unsigned int num_subbuf_order;	/*
					 * Order of number of sub-buffers/buffer
					 * for writer.
					 */
	unsigned int buf_size_order;	/* Order of buffer size */
	unsigned int extra_reader_sb:1;	/* has extra reader subbuffer ? */
	unsigned long num_subbuf;	/* Number of sub-buffers for writer */
	uint64_t start_timestamp;	/* Channel creation timestamp value */
	DECLARE_SHMP(void *, priv_data);/* Client-specific information */
	struct lttng_ust_ring_buffer_config config; /* Ring buffer configuration */
	char name[NAME_MAX];		/* Channel name */
	char padding[RB_BACKEND_CHANNEL_PADDING];
	struct lttng_ust_ring_buffer_shmp buf[];
};

#endif /* _LTTNG_RING_BUFFER_BACKEND_TYPES_H */
