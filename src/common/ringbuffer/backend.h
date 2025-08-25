/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Ring buffer backend (API).
 *
 * Credits to Steven Rostedt for proposing to use an extra-subbuffer owned by
 * the reader in flight recorder mode.
 */

#ifndef _LTTNG_RING_BUFFER_BACKEND_H
#define _LTTNG_RING_BUFFER_BACKEND_H

#include <stddef.h>
#include <unistd.h>

/* Internal helpers */
#include "backend_internal.h"
#include "frontend_internal.h"

/* Ring buffer backend API */

/* Ring buffer backend access (read/write) */

extern size_t lib_ring_buffer_read(struct lttng_ust_ring_buffer_backend *bufb,
				   size_t offset, void *dest, size_t len,
				   struct lttng_ust_shm_handle *handle)
	__attribute__((visibility("hidden")));

extern int lib_ring_buffer_read_cstr(struct lttng_ust_ring_buffer_backend *bufb,
				     size_t offset, void *dest, size_t len,
				     struct lttng_ust_shm_handle *handle)
	__attribute__((visibility("hidden")));

extern struct lttng_ust_ring_buffer_backend_pages *
	lib_ring_buffer_read_backend_pages(struct lttng_ust_ring_buffer_backend *bufb,
					   struct lttng_ust_shm_handle *handle)
	__attribute__((visibility("hidden")));

/*
 * Return the address where a given offset is located.
 * Should be used to get the current subbuffer header pointer. Given we know
 * it's never on a page boundary, it's safe to write directly to this address,
 * as long as the write is never bigger than a page size.
 */
extern void *
lib_ring_buffer_offset_address(struct lttng_ust_ring_buffer_backend *bufb,
			       size_t offset,
			       struct lttng_ust_shm_handle *handle)
	__attribute__((visibility("hidden")));

extern void *
lib_ring_buffer_read_offset_address(struct lttng_ust_ring_buffer_backend *bufb,
				    size_t offset,
				    struct lttng_ust_shm_handle *handle)
	__attribute__((visibility("hidden")));

extern struct lttng_ust_ring_buffer_backend_pages *
lib_ring_buffer_index_backend_pages(struct lttng_ust_ring_buffer_backend *bufb,
				     size_t sbidx,
				     struct lttng_ust_shm_handle *handle)
	__attribute__((visibility("hidden")));

extern struct lttng_ust_ring_buffer_backend_pages *
lib_ring_buffer_offset_backend_pages(struct lttng_ust_ring_buffer_backend *bufb,
				     size_t offset,
				     struct lttng_ust_shm_handle *handle)
	__attribute__((visibility("hidden")));

/**
 * lib_ring_buffer_write - write data to a buffer backend
 * @config : ring buffer instance configuration
 * @ctx: ring buffer context. (input arguments only)
 * @src : source pointer to copy from
 * @len : length of data to copy
 *
 * This function copies "len" bytes of data from a source pointer to a buffer
 * backend, at the current context offset. This is more or less a buffer
 * backend-specific memcpy() operation. Calls the slow path (_ring_buffer_write)
 * if copy is crossing a page boundary.
 */
static inline
void lib_ring_buffer_write(const struct lttng_ust_ring_buffer_config *config,
			   struct lttng_ust_ring_buffer_ctx *ctx,
			   const void *src, size_t len)
	__attribute__((always_inline));
static inline
void lib_ring_buffer_write(const struct lttng_ust_ring_buffer_config *config,
			   struct lttng_ust_ring_buffer_ctx *ctx,
			   const void *src, size_t len)
{
	struct lttng_ust_ring_buffer_ctx_private *ctx_private = ctx->priv;
	struct channel_backend *chanb = &ctx_private->chan->backend;
	struct lttng_ust_shm_handle *handle = ctx_private->chan->handle;
	size_t offset = ctx_private->buf_offset;
	struct lttng_ust_ring_buffer_backend_pages *backend_pages;
	void *p;

	if (caa_unlikely(!len))
		return;
	/*
	 * Underlying layer should never ask for writes across
	 * subbuffers.
	 */
	CHAN_WARN_ON(chanb, (offset & (chanb->buf_size - 1)) + len > chanb->buf_size);
	backend_pages = lib_ring_buffer_get_backend_pages_from_ctx(config, ctx);
	if (caa_unlikely(!backend_pages)) {
		if (lib_ring_buffer_backend_get_pages(config, ctx, &backend_pages))
			return;
	}
	p = shmp_index(handle, backend_pages->p, offset & (chanb->subbuf_size - 1));
	if (caa_unlikely(!p))
		return;
	lib_ring_buffer_do_copy(config, p, src, len);
	ctx_private->buf_offset += len;
}

/*
 * Copy up to @len string bytes from @src to @dest. Stop whenever a NULL
 * terminating character is found in @src. Returns the number of bytes
 * copied. Does *not* terminate @dest with NULL terminating character.
 */
static inline
size_t lib_ring_buffer_do_strcpy(const struct lttng_ust_ring_buffer_config *config,
		char *dest, const char *src, size_t len)
	__attribute__((always_inline));
static inline
size_t lib_ring_buffer_do_strcpy(
		const struct lttng_ust_ring_buffer_config *config  __attribute__((unused)),
		char *dest, const char *src, size_t len)
{
	size_t count;

	for (count = 0; count < len; count++) {
		char c;

		/*
		 * Only read source character once, in case it is
		 * modified concurrently.
		 */
		c = CMM_LOAD_SHARED(src[count]);
		if (!c)
			break;
		lib_ring_buffer_do_copy(config, &dest[count], &c, 1);
	}
	return count;
}

/**
 * lib_ring_buffer_strcpy - write string data to a buffer backend
 * @config : ring buffer instance configuration
 * @ctx: ring buffer context. (input arguments only)
 * @src : source pointer to copy from
 * @len : length of data to copy
 * @pad : character to use for padding
 *
 * This function copies @len - 1 bytes of string data from a source
 * pointer to a buffer backend, followed by a terminating '\0'
 * character, at the current context offset. This is more or less a
 * buffer backend-specific strncpy() operation. If a terminating '\0'
 * character is found in @src before @len - 1 characters are copied, pad
 * the buffer with @pad characters (e.g. '#').
 */
static inline
void lib_ring_buffer_strcpy(const struct lttng_ust_ring_buffer_config *config,
			   struct lttng_ust_ring_buffer_ctx *ctx,
			   const char *src, size_t len, char pad)
	__attribute__((always_inline));
static inline
void lib_ring_buffer_strcpy(const struct lttng_ust_ring_buffer_config *config,
			   struct lttng_ust_ring_buffer_ctx *ctx,
			   const char *src, size_t len, char pad)
{
	struct lttng_ust_ring_buffer_ctx_private *ctx_private = ctx->priv;
	struct channel_backend *chanb = &ctx_private->chan->backend;
	struct lttng_ust_shm_handle *handle = ctx_private->chan->handle;
	size_t count;
	size_t offset = ctx_private->buf_offset;
	struct lttng_ust_ring_buffer_backend_pages *backend_pages;
	void *p;

	if (caa_unlikely(!len))
		return;
	/*
	 * Underlying layer should never ask for writes across
	 * subbuffers.
	 */
	CHAN_WARN_ON(chanb, (offset & (chanb->buf_size - 1)) + len > chanb->buf_size);
	backend_pages = lib_ring_buffer_get_backend_pages_from_ctx(config, ctx);
	if (caa_unlikely(!backend_pages)) {
		if (lib_ring_buffer_backend_get_pages(config, ctx, &backend_pages))
			return;
	}
	p = shmp_index(handle, backend_pages->p, offset & (chanb->subbuf_size - 1));
	if (caa_unlikely(!p))
		return;

	count = lib_ring_buffer_do_strcpy(config, p, src, len - 1);
	offset += count;
	/* Padding */
	if (caa_unlikely(count < len - 1)) {
		size_t pad_len = len - 1 - count;

		p = shmp_index(handle, backend_pages->p, offset & (chanb->subbuf_size - 1));
		if (caa_unlikely(!p))
			return;
		lib_ring_buffer_do_memset(p, pad, pad_len);
		offset += pad_len;
	}
	/* Final '\0' */
	p = shmp_index(handle, backend_pages->p, offset & (chanb->subbuf_size - 1));
	if (caa_unlikely(!p))
		return;
	lib_ring_buffer_do_memset(p, '\0', 1);
	ctx_private->buf_offset += len;
}

/**
 * lib_ring_buffer_pstrcpy - write to a buffer backend P-string
 * @config : ring buffer instance configuration
 * @ctx: ring buffer context. (input arguments only)
 * @src : source pointer to copy from
 * @len : length of data to copy
 * @pad : character to use for padding
 *
 * This function copies up to @len bytes of data from a source pointer
 * to a Pascal String into the buffer backend. If a terminating '\0'
 * character is found in @src before @len characters are copied, pad the
 * buffer with @pad characters (e.g.  '\0').
 *
 * The length of the pascal strings in the ring buffer is explicit: it
 * is either the array or sequence length.
 */
static inline
void lib_ring_buffer_pstrcpy(const struct lttng_ust_ring_buffer_config *config,
			   struct lttng_ust_ring_buffer_ctx *ctx,
			   const char *src, size_t len, char pad)
	__attribute__((always_inline));
static inline
void lib_ring_buffer_pstrcpy(const struct lttng_ust_ring_buffer_config *config,
			   struct lttng_ust_ring_buffer_ctx *ctx,
			   const char *src, size_t len, char pad)
{
	struct lttng_ust_ring_buffer_ctx_private *ctx_private = ctx->priv;
	struct channel_backend *chanb = &ctx_private->chan->backend;
	struct lttng_ust_shm_handle *handle = ctx_private->chan->handle;
	size_t count;
	size_t offset = ctx_private->buf_offset;
	struct lttng_ust_ring_buffer_backend_pages *backend_pages;
	void *p;

	if (caa_unlikely(!len))
		return;
	/*
	 * Underlying layer should never ask for writes across
	 * subbuffers.
	 */
	CHAN_WARN_ON(chanb, (offset & (chanb->buf_size - 1)) + len > chanb->buf_size);
	backend_pages = lib_ring_buffer_get_backend_pages_from_ctx(config, ctx);
	if (caa_unlikely(!backend_pages)) {
		if (lib_ring_buffer_backend_get_pages(config, ctx, &backend_pages))
			return;
	}
	p = shmp_index(handle, backend_pages->p, offset & (chanb->subbuf_size - 1));
	if (caa_unlikely(!p))
		return;

	count = lib_ring_buffer_do_strcpy(config, p, src, len);
	offset += count;
	/* Padding */
	if (caa_unlikely(count < len)) {
		size_t pad_len = len - count;

		p = shmp_index(handle, backend_pages->p, offset & (chanb->subbuf_size - 1));
		if (caa_unlikely(!p))
			return;
		lib_ring_buffer_do_memset(p, pad, pad_len);
	}
	ctx_private->buf_offset += len;
}

/*
 * This accessor counts the number of unread records in a buffer.
 * It only provides a consistent value if no reads not writes are performed
 * concurrently.
 */
static inline
unsigned long lib_ring_buffer_get_records_unread(
				const struct lttng_ust_ring_buffer_config *config,
				struct lttng_ust_ring_buffer *buf,
				struct lttng_ust_shm_handle *handle)
{
	struct lttng_ust_ring_buffer_backend *bufb = &buf->backend;
	struct lttng_ust_ring_buffer_backend_pages_shmp *rpages;
	struct lttng_ust_ring_buffer_backend_pages *backend_pages;
	unsigned long records_unread = 0, sb_bindex;
	unsigned int i;
	struct lttng_ust_ring_buffer_channel *chan;

	chan = shmp(handle, bufb->chan);
	if (!chan)
		return 0;
	for (i = 0; i < chan->backend.num_subbuf; i++) {
		struct lttng_ust_ring_buffer_backend_subbuffer *wsb;

		wsb = shmp_index(handle, bufb->buf_wsb, i);
		if (!wsb)
			return 0;
		sb_bindex = subbuffer_id_get_index(config, wsb->id);
		rpages = shmp_index(handle, bufb->array, sb_bindex);
		if (!rpages)
			return 0;
		backend_pages = shmp(handle, rpages->shmp);
		if (!backend_pages)
			return 0;
		records_unread += v_read(config, &backend_pages->records_unread);
	}
	sb_bindex = subbuffer_id_get_index(config, bufb->buf_rsb.id);
	rpages = shmp_index(handle, bufb->array, sb_bindex);
	if (!rpages)
		return 0;
	backend_pages = shmp(handle, rpages->shmp);
	if (!backend_pages)
		return 0;
	records_unread += v_read(config, &backend_pages->records_unread);
	return records_unread;
}

#endif /* _LTTNG_RING_BUFFER_BACKEND_H */
