#ifndef _LINUX_RING_BUFFER_BACKEND_TYPES_H
#define _LINUX_RING_BUFFER_BACKEND_TYPES_H

/*
 * linux/ringbuffer/backend_types.h
 *
 * Copyright (C) 2008-2010 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Ring buffer backend (types).
 *
 * Dual LGPL v2.1/GPL v2 license.
 */

#include "shm.h"

struct lib_ring_buffer_backend_pages {
	unsigned long mmap_offset;	/* offset of the subbuffer in mmap */
	union v_atomic records_commit;	/* current records committed count */
	union v_atomic records_unread;	/* records to read */
	unsigned long data_size;	/* Amount of data to read from subbuf */
	DECLARE_SHMP(char, p);		/* Backing memory map */
};

struct lib_ring_buffer_backend_subbuffer {
	/* Identifier for subbuf backend pages. Exchanged atomically. */
	unsigned long id;		/* backend subbuffer identifier */
};

/*
 * Forward declaration of frontend-specific channel and ring_buffer.
 */
struct channel;
struct lib_ring_buffer;

struct lib_ring_buffer_backend {
	/* Array of ring_buffer_backend_subbuffer for writer */
	DECLARE_SHMP(struct lib_ring_buffer_backend_subbuffer, buf_wsb);
	/* ring_buffer_backend_subbuffer for reader */
	struct lib_ring_buffer_backend_subbuffer buf_rsb;
	/*
	 * Pointer array of backend pages, for whole buffer.
	 * Indexed by ring_buffer_backend_subbuffer identifier (id) index.
	 */
	DECLARE_SHMP(struct lib_ring_buffer_backend_pages *, array);
	DECLARE_SHMP(char, memory_map);	/* memory mapping */

	DECLARE_SHMP(struct channel, chan);	/* Associated channel */
	int cpu;			/* This buffer's cpu. -1 if global. */
	union v_atomic records_read;	/* Number of records read */
	unsigned int allocated:1;	/* Bool: is buffer allocated ? */
};

struct channel_backend {
	unsigned long buf_size;		/* Size of the buffer */
	unsigned long subbuf_size;	/* Sub-buffer size */
	unsigned int subbuf_size_order;	/* Order of sub-buffer size */
	unsigned int num_subbuf_order;	/*
					 * Order of number of sub-buffers/buffer
					 * for writer.
					 */
	unsigned int buf_size_order;	/* Order of buffer size */
	int extra_reader_sb:1;		/* Bool: has extra reader subbuffer */
	DECLARE_SHMP(struct lib_ring_buffer, buf); /* Channel per-cpu buffers */
	unsigned long num_subbuf;	/* Number of sub-buffers for writer */
	u64 start_tsc;			/* Channel creation TSC value */
	void *priv;			/* Client-specific information */
	const struct lib_ring_buffer_config *config; /* Ring buffer configuration */
	char name[NAME_MAX];		/* Channel name */
};

#endif /* _LINUX_RING_BUFFER_BACKEND_TYPES_H */
