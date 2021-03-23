/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2010-2021 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Ring buffer context header.
 */

#ifndef _LTTNG_RING_BUFFER_CONTEXT_H
#define _LTTNG_RING_BUFFER_CONTEXT_H

#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <urcu/arch.h>
#include <string.h>

#include <lttng/ust-tracer.h>
#include <lttng/ust-utils.h>
#include <lttng/ust-compiler.h>

struct lttng_ust_lib_ring_buffer;
struct lttng_ust_lib_ring_buffer_channel;
struct lttng_ust_lib_ring_buffer_ctx;

/*
 * ring buffer context
 *
 * Context passed to lib_ring_buffer_reserve(), lib_ring_buffer_commit(),
 * lib_ring_buffer_try_discard_reserve(), lib_ring_buffer_align_ctx() and
 * lib_ring_buffer_write().
 *
 * IMPORTANT: this structure is part of the ABI between the probe and
 * UST. Fields need to be only added at the end, never reordered, never
 * removed.
 *
 * The field @struct_size should be used to determine the size of the
 * structure. It should be queried before using additional fields added
 * at the end of the structure.
 */
struct lttng_ust_lib_ring_buffer_ctx {
	uint32_t struct_size;			/* Size of this structure. */

	/* input received by lib_ring_buffer_reserve(). */
	struct lttng_ust_lib_ring_buffer_channel *chan; /* channel */
	void *priv;				/* client private data */
	size_t data_size;			/* size of payload */
	int largest_align;			/*
						 * alignment of the largest element
						 * in the payload
						 */

	/* output from lib_ring_buffer_reserve() */
	int reserve_cpu;			/* processor id updated by the reserve */
	size_t slot_size;			/* size of the reserved slot */
	unsigned long buf_offset;		/* offset following the record header */
	unsigned long pre_offset;		/*
						 * Initial offset position _before_
						 * the record is written. Positioned
						 * prior to record header alignment
						 * padding.
						 */
	uint64_t tsc;				/* time-stamp counter value */
	unsigned int rflags;			/* reservation flags */
	void *ip;				/* caller ip address */

	struct lttng_ust_lib_ring_buffer *buf;	/*
						 * buffer corresponding to processor id
						 * for this channel
						 */
	struct lttng_ust_lib_ring_buffer_backend_pages *backend_pages;

	/* End of base ABI. Fields below should be used after checking struct_size. */
};

/**
 * lib_ring_buffer_ctx_init - initialize ring buffer context
 * @ctx: ring buffer context to initialize
 * @chan: channel
 * @priv: client private data
 * @data_size: size of record data payload
 * @largest_align: largest alignment within data payload types
 */
static inline lttng_ust_notrace
void lib_ring_buffer_ctx_init(struct lttng_ust_lib_ring_buffer_ctx *ctx,
			      struct lttng_ust_lib_ring_buffer_channel *chan,
			      void *priv, size_t data_size, int largest_align);
static inline
void lib_ring_buffer_ctx_init(struct lttng_ust_lib_ring_buffer_ctx *ctx,
			      struct lttng_ust_lib_ring_buffer_channel *chan,
			      void *priv, size_t data_size, int largest_align)
{
	ctx->struct_size = sizeof(struct lttng_ust_lib_ring_buffer_ctx);
	ctx->chan = chan;
	ctx->priv = priv;
	ctx->data_size = data_size;
	ctx->reserve_cpu = -1;
	ctx->largest_align = largest_align;
	ctx->rflags = 0;
	ctx->ip = 0;
}

/*
 * We need to define RING_BUFFER_ALIGN_ATTR so it is known early at
 * compile-time. We have to duplicate the "config->align" information and the
 * definition here because config->align is used both in the slow and fast
 * paths, but RING_BUFFER_ALIGN_ATTR is only available for the client code.
 */
#ifdef RING_BUFFER_ALIGN

# define RING_BUFFER_ALIGN_ATTR		/* Default arch alignment */

/*
 * Calculate the offset needed to align the type.
 * size_of_type must be non-zero.
 */
static inline lttng_ust_notrace
unsigned int lib_ring_buffer_align(size_t align_drift, size_t size_of_type);
static inline
unsigned int lib_ring_buffer_align(size_t align_drift, size_t size_of_type)
{
	return lttng_ust_offset_align(align_drift, size_of_type);
}

#else

# define RING_BUFFER_ALIGN_ATTR __attribute__((packed))

/*
 * Calculate the offset needed to align the type.
 * size_of_type must be non-zero.
 */
static inline lttng_ust_notrace
unsigned int lib_ring_buffer_align(size_t align_drift, size_t size_of_type);
static inline
unsigned int lib_ring_buffer_align(size_t align_drift, size_t size_of_type)
{
	return 0;
}

#endif

/**
 * lib_ring_buffer_align_ctx - Align context offset on "alignment"
 * @ctx: ring buffer context.
 */
static inline lttng_ust_notrace
void lib_ring_buffer_align_ctx(struct lttng_ust_lib_ring_buffer_ctx *ctx,
			   size_t alignment);
static inline
void lib_ring_buffer_align_ctx(struct lttng_ust_lib_ring_buffer_ctx *ctx,
			   size_t alignment)
{
	ctx->buf_offset += lib_ring_buffer_align(ctx->buf_offset,
						 alignment);
}

#endif /* _LTTNG_RING_BUFFER_CONTEXT_H */
