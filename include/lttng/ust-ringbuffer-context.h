// SPDX-FileCopyrightText: 2010-2021 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
//
// SPDX-License-Identifier: MIT

/*
 * Ring buffer context header.
 */

#ifndef _LTTNG_UST_RING_BUFFER_CONTEXT_H
#define _LTTNG_UST_RING_BUFFER_CONTEXT_H

#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <urcu/arch.h>
#include <string.h>

#include <lttng/ust-tracer.h>
#include <lttng/ust-utils.h>
#include <lttng/ust-compiler.h>

struct lttng_ust_ring_buffer;
struct lttng_ust_ring_buffer_channel;
struct lttng_ust_ring_buffer_ctx;
struct lttng_ust_ring_buffer_ctx_private;
struct lttng_ust_probe_ctx;

/*
 * ring buffer context
 *
 * IMPORTANT: this structure is part of the ABI between the probe and
 * UST. Fields need to be only added at the end, never reordered, never
 * removed.
 *
 * The field @struct_size should be used to determine the size of the
 * structure. It should be queried before using additional fields added
 * at the end of the structure.
 */
struct lttng_ust_ring_buffer_ctx {
	uint32_t struct_size;			/* Size of this structure. */

	void *client_priv;			/* Ring buffer client private data */
	size_t data_size;			/* size of payload */
	int largest_align;			/*
						 * alignment of the largest element
						 * in the payload
						 */
	struct lttng_ust_probe_ctx *probe_ctx;	/* Probe context */

	/* Private ring buffer context, set by reserve callback. */
	struct lttng_ust_ring_buffer_ctx_private *priv;

	/* End of base ABI. Fields below should be used after checking struct_size. */
};

/**
 * lttng_ust_ring_buffer_ctx_init - initialize ring buffer context
 * @ctx: ring buffer context to initialize
 * @client_priv: client private data
 * @data_size: size of record data payload
 * @largest_align: largest alignment within data payload types
 * @ip: caller ip address
 */
static inline
void lttng_ust_ring_buffer_ctx_init(struct lttng_ust_ring_buffer_ctx *ctx,
					void *client_priv, size_t data_size, size_t largest_align,
					struct lttng_ust_probe_ctx *probe_ctx)
	lttng_ust_notrace;
static inline
void lttng_ust_ring_buffer_ctx_init(struct lttng_ust_ring_buffer_ctx *ctx,
					void *client_priv, size_t data_size, size_t largest_align,
					struct lttng_ust_probe_ctx *probe_ctx)
{
	ctx->struct_size = sizeof(struct lttng_ust_ring_buffer_ctx);
	ctx->client_priv = client_priv;
	ctx->data_size = data_size;
	ctx->largest_align = largest_align;
	ctx->probe_ctx = probe_ctx;
	ctx->priv = NULL;
}

/*
 * We need to define LTTNG_UST_RING_BUFFER_ALIGN_ATTR so it is known early at
 * compile-time. We have to duplicate the "config->align" information and the
 * definition here because config->align is used both in the slow and fast
 * paths, but LTTNG_UST_RING_BUFFER_ALIGN_ATTR is only available for the client
 * code.
 */
#ifdef LTTNG_UST_RING_BUFFER_NATURAL_ALIGN

# define LTTNG_UST_RING_BUFFER_ALIGN_ATTR	/* Default arch alignment */

/*
 * lttng_ust_ring_buffer_align - Calculate the offset needed to align the type.
 * @align_drift:  object offset from an "alignment"-aligned address.
 * @size_of_type: Must be non-zero, power of 2.
 */
static inline
unsigned int lttng_ust_ring_buffer_align(size_t align_drift, size_t size_of_type)
	lttng_ust_notrace;
static inline
unsigned int lttng_ust_ring_buffer_align(size_t align_drift, size_t size_of_type)
{
	return lttng_ust_offset_align(align_drift, size_of_type);
}

#else

# define LTTNG_UST_RING_BUFFER_ALIGN_ATTR __attribute__((packed))

/*
 * lttng_ust_ring_buffer_align - Calculate the offset needed to align the type.
 * @align_drift:  object offset from an "alignment"-aligned address.
 * @size_of_type: Must be non-zero, power of 2.
 */
static inline
unsigned int lttng_ust_ring_buffer_align(size_t align_drift, size_t size_of_type)
	lttng_ust_notrace;
static inline
unsigned int lttng_ust_ring_buffer_align(size_t align_drift __attribute__((unused)),
		size_t size_of_type __attribute__((unused)))
{
	/*
	 * On architectures with efficient unaligned memory access, the content
	 * of the ringbuffer is packed and so the offset is always zero.
	 */
	return 0;
}

#endif

#endif /* _LTTNG_UST_RING_BUFFER_CONTEXT_H */
