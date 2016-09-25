#ifndef _LTTNG_RING_BUFFER_BACKEND_H
#define _LTTNG_RING_BUFFER_BACKEND_H

/*
 * libringbuffer/backend.h
 *
 * Ring buffer backend (API).
 *
 * Copyright (C) 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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
 * Credits to Steven Rostedt for proposing to use an extra-subbuffer owned by
 * the reader in flight recorder mode.
 */

#include <unistd.h>

/* Internal helpers */
#include "backend_internal.h"
#include "frontend_internal.h"

/* Ring buffer backend API */

/* Ring buffer backend access (read/write) */

extern size_t lib_ring_buffer_read(struct lttng_ust_lib_ring_buffer_backend *bufb,
				   size_t offset, void *dest, size_t len,
				   struct lttng_ust_shm_handle *handle);

extern int lib_ring_buffer_read_cstr(struct lttng_ust_lib_ring_buffer_backend *bufb,
				     size_t offset, void *dest, size_t len,
				     struct lttng_ust_shm_handle *handle);

/*
 * Return the address where a given offset is located.
 * Should be used to get the current subbuffer header pointer. Given we know
 * it's never on a page boundary, it's safe to write directly to this address,
 * as long as the write is never bigger than a page size.
 */
extern void *
lib_ring_buffer_offset_address(struct lttng_ust_lib_ring_buffer_backend *bufb,
			       size_t offset,
			       struct lttng_ust_shm_handle *handle);
extern void *
lib_ring_buffer_read_offset_address(struct lttng_ust_lib_ring_buffer_backend *bufb,
				    size_t offset,
				    struct lttng_ust_shm_handle *handle);

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
static inline __attribute__((always_inline))
void lib_ring_buffer_write(const struct lttng_ust_lib_ring_buffer_config *config,
			   struct lttng_ust_lib_ring_buffer_ctx *ctx,
			   const void *src, size_t len)
{
	struct channel_backend *chanb = &ctx->chan->backend;
	struct lttng_ust_shm_handle *handle = ctx->handle;
	size_t offset = ctx->buf_offset;
	struct lttng_ust_lib_ring_buffer_backend_pages *backend_pages;
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
	ctx->buf_offset += len;
}

/*
 * Copy up to @len string bytes from @src to @dest. Stop whenever a NULL
 * terminating character is found in @src. Returns the number of bytes
 * copied. Does *not* terminate @dest with NULL terminating character.
 */
static inline __attribute__((always_inline))
size_t lib_ring_buffer_do_strcpy(const struct lttng_ust_lib_ring_buffer_config *config,
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
static inline __attribute__((always_inline))
void lib_ring_buffer_strcpy(const struct lttng_ust_lib_ring_buffer_config *config,
			   struct lttng_ust_lib_ring_buffer_ctx *ctx,
			   const char *src, size_t len, int pad)
{
	struct channel_backend *chanb = &ctx->chan->backend;
	struct lttng_ust_shm_handle *handle = ctx->handle;
	size_t count;
	size_t offset = ctx->buf_offset;
	struct lttng_ust_lib_ring_buffer_backend_pages *backend_pages;
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
	ctx->buf_offset += len;
}

/*
 * This accessor counts the number of unread records in a buffer.
 * It only provides a consistent value if no reads not writes are performed
 * concurrently.
 */
static inline
unsigned long lib_ring_buffer_get_records_unread(
				const struct lttng_ust_lib_ring_buffer_config *config,
				struct lttng_ust_lib_ring_buffer *buf,
				struct lttng_ust_shm_handle *handle)
{
	struct lttng_ust_lib_ring_buffer_backend *bufb = &buf->backend;
	unsigned long records_unread = 0, sb_bindex;
	unsigned int i;
	struct channel *chan;

	chan = shmp(handle, bufb->chan);
	if (!chan)
		return 0;
	for (i = 0; i < chan->backend.num_subbuf; i++) {
		struct lttng_ust_lib_ring_buffer_backend_subbuffer *wsb;
		struct lttng_ust_lib_ring_buffer_backend_pages_shmp *rpages;
		struct lttng_ust_lib_ring_buffer_backend_pages *backend_pages;

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
	if (config->mode == RING_BUFFER_OVERWRITE) {
		struct lttng_ust_lib_ring_buffer_backend_pages_shmp *rpages;
		struct lttng_ust_lib_ring_buffer_backend_pages *backend_pages;

		sb_bindex = subbuffer_id_get_index(config, bufb->buf_rsb.id);
		rpages = shmp_index(handle, bufb->array, sb_bindex);
		if (!rpages)
			return 0;
		backend_pages = shmp(handle, rpages->shmp);
		if (!backend_pages)
			return 0;
		records_unread += v_read(config, &backend_pages->records_unread);
	}
	return records_unread;
}

#endif /* _LTTNG_RING_BUFFER_BACKEND_H */
