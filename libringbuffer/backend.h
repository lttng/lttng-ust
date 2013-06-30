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
static inline
void lib_ring_buffer_write(const struct lttng_ust_lib_ring_buffer_config *config,
			   struct lttng_ust_lib_ring_buffer_ctx *ctx,
			   const void *src, size_t len)
{
	struct lttng_ust_lib_ring_buffer_backend *bufb = &ctx->buf->backend;
	struct channel_backend *chanb = &ctx->chan->backend;
	struct lttng_ust_shm_handle *handle = ctx->handle;
	size_t sbidx;
	size_t offset = ctx->buf_offset;
	struct lttng_ust_lib_ring_buffer_backend_pages_shmp *rpages;
	unsigned long sb_bindex, id;

	if (caa_unlikely(!len))
		return;
	offset &= chanb->buf_size - 1;
	sbidx = offset >> chanb->subbuf_size_order;
	id = shmp_index(handle, bufb->buf_wsb, sbidx)->id;
	sb_bindex = subbuffer_id_get_index(config, id);
	rpages = shmp_index(handle, bufb->array, sb_bindex);
	CHAN_WARN_ON(ctx->chan,
		     config->mode == RING_BUFFER_OVERWRITE
		     && subbuffer_id_is_noref(config, id));
	/*
	 * Underlying layer should never ask for writes across
	 * subbuffers.
	 */
	CHAN_WARN_ON(chanb, offset >= chanb->buf_size);
	lib_ring_buffer_do_copy(config,
				shmp_index(handle, shmp(handle, rpages->shmp)->p, offset & (chanb->subbuf_size - 1)),
				src, len);
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
	struct lttng_ust_lib_ring_buffer_backend_pages_shmp *pages;
	unsigned long records_unread = 0, sb_bindex, id;
	unsigned int i;

	for (i = 0; i < shmp(handle, bufb->chan)->backend.num_subbuf; i++) {
		id = shmp_index(handle, bufb->buf_wsb, i)->id;
		sb_bindex = subbuffer_id_get_index(config, id);
		pages = shmp_index(handle, bufb->array, sb_bindex);
		records_unread += v_read(config, &shmp(handle, pages->shmp)->records_unread);
	}
	if (config->mode == RING_BUFFER_OVERWRITE) {
		id = bufb->buf_rsb.id;
		sb_bindex = subbuffer_id_get_index(config, id);
		pages = shmp_index(handle, bufb->array, sb_bindex);
		records_unread += v_read(config, &shmp(handle, pages->shmp)->records_unread);
	}
	return records_unread;
}

#endif /* _LTTNG_RING_BUFFER_BACKEND_H */
