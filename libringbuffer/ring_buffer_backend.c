/*
 * ring_buffer_backend.c
 *
 * Copyright (C) 2005-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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
 */

#define _GNU_SOURCE
#define _LGPL_SOURCE
#include <unistd.h>
#include <urcu/arch.h>
#include <limits.h>

#include <lttng/ringbuffer-config.h>
#include "vatomic.h"
#include "backend.h"
#include "frontend.h"
#include "smp.h"
#include "shm.h"

/**
 * lib_ring_buffer_backend_allocate - allocate a channel buffer
 * @config: ring buffer instance configuration
 * @buf: the buffer struct
 * @size: total size of the buffer
 * @num_subbuf: number of subbuffers
 * @extra_reader_sb: need extra subbuffer for reader
 */
static
int lib_ring_buffer_backend_allocate(const struct lttng_ust_lib_ring_buffer_config *config,
				     struct lttng_ust_lib_ring_buffer_backend *bufb,
				     size_t size, size_t num_subbuf,
				     int extra_reader_sb,
				     struct lttng_ust_shm_handle *handle,
				     struct shm_object *shmobj)
{
	struct channel_backend *chanb;
	unsigned long subbuf_size, mmap_offset = 0;
	unsigned long num_subbuf_alloc;
	unsigned long i;
	long page_size;

	chanb = &shmp(handle, bufb->chan)->backend;
	if (!chanb)
		return -EINVAL;

	subbuf_size = chanb->subbuf_size;
	num_subbuf_alloc = num_subbuf;

	if (extra_reader_sb)
		num_subbuf_alloc++;

	page_size = sysconf(_SC_PAGE_SIZE);
	if (page_size <= 0) {
		goto page_size_error;
	}

	align_shm(shmobj, __alignof__(struct lttng_ust_lib_ring_buffer_backend_pages_shmp));
	set_shmp(bufb->array, zalloc_shm(shmobj,
			sizeof(struct lttng_ust_lib_ring_buffer_backend_pages_shmp) * num_subbuf_alloc));
	if (caa_unlikely(!shmp(handle, bufb->array)))
		goto array_error;

	/*
	 * This is the largest element (the buffer pages) which needs to
	 * be aligned on page size.
	 */
	align_shm(shmobj, page_size);
	set_shmp(bufb->memory_map, zalloc_shm(shmobj,
			subbuf_size * num_subbuf_alloc));
	if (caa_unlikely(!shmp(handle, bufb->memory_map)))
		goto memory_map_error;

	/* Allocate backend pages array elements */
	for (i = 0; i < num_subbuf_alloc; i++) {
		align_shm(shmobj, __alignof__(struct lttng_ust_lib_ring_buffer_backend_pages));
		set_shmp(shmp_index(handle, bufb->array, i)->shmp,
			zalloc_shm(shmobj,
				sizeof(struct lttng_ust_lib_ring_buffer_backend_pages)));
		if (!shmp(handle, shmp_index(handle, bufb->array, i)->shmp))
			goto free_array;
	}

	/* Allocate write-side subbuffer table */
	align_shm(shmobj, __alignof__(struct lttng_ust_lib_ring_buffer_backend_subbuffer));
	set_shmp(bufb->buf_wsb, zalloc_shm(shmobj,
				sizeof(struct lttng_ust_lib_ring_buffer_backend_subbuffer)
				* num_subbuf));
	if (caa_unlikely(!shmp(handle, bufb->buf_wsb)))
		goto free_array;

	for (i = 0; i < num_subbuf; i++) {
		struct lttng_ust_lib_ring_buffer_backend_subbuffer *sb;

		sb = shmp_index(handle, bufb->buf_wsb, i);
		if (!sb)
			goto free_array;
		sb->id = subbuffer_id(config, 0, 1, i);
	}

	/* Assign read-side subbuffer table */
	if (extra_reader_sb)
		bufb->buf_rsb.id = subbuffer_id(config, 0, 1,
						num_subbuf_alloc - 1);
	else
		bufb->buf_rsb.id = subbuffer_id(config, 0, 1, 0);

	/* Allocate subbuffer packet counter table */
	align_shm(shmobj, __alignof__(struct lttng_ust_lib_ring_buffer_backend_counts));
	set_shmp(bufb->buf_cnt, zalloc_shm(shmobj,
				sizeof(struct lttng_ust_lib_ring_buffer_backend_counts)
				* num_subbuf));
	if (caa_unlikely(!shmp(handle, bufb->buf_cnt)))
		goto free_wsb;

	/* Assign pages to page index */
	for (i = 0; i < num_subbuf_alloc; i++) {
		struct lttng_ust_lib_ring_buffer_backend_pages_shmp *sbp;
		struct lttng_ust_lib_ring_buffer_backend_pages *pages;
		struct shm_ref ref;

		ref.index = bufb->memory_map._ref.index;
		ref.offset = bufb->memory_map._ref.offset;
		ref.offset += i * subbuf_size;

		sbp = shmp_index(handle, bufb->array, i);
		if (!sbp)
			goto free_array;
		pages = shmp(handle, sbp->shmp);
		if (!pages)
			goto free_array;
		set_shmp(pages->p, ref);
		if (config->output == RING_BUFFER_MMAP) {
			pages->mmap_offset = mmap_offset;
			mmap_offset += subbuf_size;
		}
	}
	return 0;

free_wsb:
	/* bufb->buf_wsb will be freed by shm teardown */
free_array:
	/* bufb->array[i] will be freed by shm teardown */
memory_map_error:
	/* bufb->array will be freed by shm teardown */
array_error:
page_size_error:
	return -ENOMEM;
}

int lib_ring_buffer_backend_create(struct lttng_ust_lib_ring_buffer_backend *bufb,
				   struct channel_backend *chanb, int cpu,
				   struct lttng_ust_shm_handle *handle,
				   struct shm_object *shmobj)
{
	const struct lttng_ust_lib_ring_buffer_config *config = &chanb->config;

	set_shmp(bufb->chan, handle->chan._ref);
	bufb->cpu = cpu;

	return lib_ring_buffer_backend_allocate(config, bufb, chanb->buf_size,
						chanb->num_subbuf,
						chanb->extra_reader_sb,
						handle, shmobj);
}

void lib_ring_buffer_backend_reset(struct lttng_ust_lib_ring_buffer_backend *bufb,
				   struct lttng_ust_shm_handle *handle)
{
	struct channel_backend *chanb;
	const struct lttng_ust_lib_ring_buffer_config *config;
	unsigned long num_subbuf_alloc;
	unsigned int i;

	chanb = &shmp(handle, bufb->chan)->backend;
	if (!chanb)
		return;
	config = &chanb->config;

	num_subbuf_alloc = chanb->num_subbuf;
	if (chanb->extra_reader_sb)
		num_subbuf_alloc++;

	for (i = 0; i < chanb->num_subbuf; i++) {
		struct lttng_ust_lib_ring_buffer_backend_subbuffer *sb;

		sb = shmp_index(handle, bufb->buf_wsb, i);
		if (!sb)
			return;
		sb->id = subbuffer_id(config, 0, 1, i);
	}
	if (chanb->extra_reader_sb)
		bufb->buf_rsb.id = subbuffer_id(config, 0, 1,
						num_subbuf_alloc - 1);
	else
		bufb->buf_rsb.id = subbuffer_id(config, 0, 1, 0);

	for (i = 0; i < num_subbuf_alloc; i++) {
		struct lttng_ust_lib_ring_buffer_backend_pages_shmp *sbp;
		struct lttng_ust_lib_ring_buffer_backend_pages *pages;

		sbp = shmp_index(handle, bufb->array, i);
		if (!sbp)
			return;
		pages = shmp(handle, sbp->shmp);
		if (!pages)
			return;
		/* Don't reset mmap_offset */
		v_set(config, &pages->records_commit, 0);
		v_set(config, &pages->records_unread, 0);
		pages->data_size = 0;
		/* Don't reset backend page and virt addresses */
	}
	/* Don't reset num_pages_per_subbuf, cpu, allocated */
	v_set(config, &bufb->records_read, 0);
}

/*
 * The frontend is responsible for also calling ring_buffer_backend_reset for
 * each buffer when calling channel_backend_reset.
 */
void channel_backend_reset(struct channel_backend *chanb)
{
	struct channel *chan = caa_container_of(chanb, struct channel, backend);
	const struct lttng_ust_lib_ring_buffer_config *config = &chanb->config;

	/*
	 * Don't reset buf_size, subbuf_size, subbuf_size_order,
	 * num_subbuf_order, buf_size_order, extra_reader_sb, num_subbuf,
	 * priv, notifiers, config, cpumask and name.
	 */
	chanb->start_tsc = config->cb.ring_buffer_clock_read(chan);
}

/**
 * channel_backend_init - initialize a channel backend
 * @chanb: channel backend
 * @name: channel name
 * @config: client ring buffer configuration
 * @parent: dentry of parent directory, %NULL for root directory
 * @subbuf_size: size of sub-buffers (> page size, power of 2)
 * @num_subbuf: number of sub-buffers (power of 2)
 * @lttng_ust_shm_handle: shared memory handle
 * @stream_fds: stream file descriptors.
 *
 * Returns channel pointer if successful, %NULL otherwise.
 *
 * Creates per-cpu channel buffers using the sizes and attributes
 * specified.  The created channel buffer files will be named
 * name_0...name_N-1.  File permissions will be %S_IRUSR.
 *
 * Called with CPU hotplug disabled.
 */
int channel_backend_init(struct channel_backend *chanb,
			 const char *name,
			 const struct lttng_ust_lib_ring_buffer_config *config,
			 size_t subbuf_size, size_t num_subbuf,
			 struct lttng_ust_shm_handle *handle,
			 const int *stream_fds)
{
	struct channel *chan = caa_container_of(chanb, struct channel, backend);
	unsigned int i;
	int ret;
	size_t shmsize = 0, num_subbuf_alloc;
	long page_size;

	if (!name)
		return -EPERM;

	page_size = sysconf(_SC_PAGE_SIZE);
	if (page_size <= 0) {
		return -ENOMEM;
	}
	/* Check that the subbuffer size is larger than a page. */
	if (subbuf_size < page_size)
		return -EINVAL;

	/*
	 * Make sure the number of subbuffers and subbuffer size are
	 * power of 2, and nonzero.
	 */
	if (!subbuf_size || (subbuf_size & (subbuf_size - 1)))
		return -EINVAL;
	if (!num_subbuf || (num_subbuf & (num_subbuf - 1)))
		return -EINVAL;
	/*
	 * Overwrite mode buffers require at least 2 subbuffers per
	 * buffer.
	 */
	if (config->mode == RING_BUFFER_OVERWRITE && num_subbuf < 2)
		return -EINVAL;

	ret = subbuffer_id_check_index(config, num_subbuf);
	if (ret)
		return ret;

	chanb->buf_size = num_subbuf * subbuf_size;
	chanb->subbuf_size = subbuf_size;
	chanb->buf_size_order = get_count_order(chanb->buf_size);
	chanb->subbuf_size_order = get_count_order(subbuf_size);
	chanb->num_subbuf_order = get_count_order(num_subbuf);
	chanb->extra_reader_sb =
			(config->mode == RING_BUFFER_OVERWRITE) ? 1 : 0;
	chanb->num_subbuf = num_subbuf;
	strncpy(chanb->name, name, NAME_MAX);
	chanb->name[NAME_MAX - 1] = '\0';
	memcpy(&chanb->config, config, sizeof(*config));

	/* Per-cpu buffer size: control (prior to backend) */
	shmsize = offset_align(shmsize, __alignof__(struct lttng_ust_lib_ring_buffer));
	shmsize += sizeof(struct lttng_ust_lib_ring_buffer);

	/* Per-cpu buffer size: backend */
	/* num_subbuf + 1 is the worse case */
	num_subbuf_alloc = num_subbuf + 1;
	shmsize += offset_align(shmsize, __alignof__(struct lttng_ust_lib_ring_buffer_backend_pages_shmp));
	shmsize += sizeof(struct lttng_ust_lib_ring_buffer_backend_pages_shmp) * num_subbuf_alloc;
	shmsize += offset_align(shmsize, page_size);
	shmsize += subbuf_size * num_subbuf_alloc;
	shmsize += offset_align(shmsize, __alignof__(struct lttng_ust_lib_ring_buffer_backend_pages));
	shmsize += sizeof(struct lttng_ust_lib_ring_buffer_backend_pages) * num_subbuf_alloc;
	shmsize += offset_align(shmsize, __alignof__(struct lttng_ust_lib_ring_buffer_backend_subbuffer));
	shmsize += sizeof(struct lttng_ust_lib_ring_buffer_backend_subbuffer) * num_subbuf;
	shmsize += offset_align(shmsize, __alignof__(struct lttng_ust_lib_ring_buffer_backend_counts));
	shmsize += sizeof(struct lttng_ust_lib_ring_buffer_backend_counts) * num_subbuf;
	/* Per-cpu buffer size: control (after backend) */
	shmsize += offset_align(shmsize, __alignof__(struct commit_counters_hot));
	shmsize += sizeof(struct commit_counters_hot) * num_subbuf;
	shmsize += offset_align(shmsize, __alignof__(struct commit_counters_cold));
	shmsize += sizeof(struct commit_counters_cold) * num_subbuf;

	if (config->alloc == RING_BUFFER_ALLOC_PER_CPU) {
		struct lttng_ust_lib_ring_buffer *buf;
		/*
		 * We need to allocate for all possible cpus.
		 */
		for_each_possible_cpu(i) {
			struct shm_object *shmobj;

			shmobj = shm_object_table_alloc(handle->table, shmsize,
					SHM_OBJECT_SHM, stream_fds[i], i);
			if (!shmobj)
				goto end;
			align_shm(shmobj, __alignof__(struct lttng_ust_lib_ring_buffer));
			set_shmp(chanb->buf[i].shmp, zalloc_shm(shmobj, sizeof(struct lttng_ust_lib_ring_buffer)));
			buf = shmp(handle, chanb->buf[i].shmp);
			if (!buf)
				goto end;
			set_shmp(buf->self, chanb->buf[i].shmp._ref);
			ret = lib_ring_buffer_create(buf, chanb, i,
					handle, shmobj);
			if (ret)
				goto free_bufs;	/* cpu hotplug locked */
		}
	} else {
		struct shm_object *shmobj;
		struct lttng_ust_lib_ring_buffer *buf;

		shmobj = shm_object_table_alloc(handle->table, shmsize,
					SHM_OBJECT_SHM, stream_fds[0], -1);
		if (!shmobj)
			goto end;
		align_shm(shmobj, __alignof__(struct lttng_ust_lib_ring_buffer));
		set_shmp(chanb->buf[0].shmp, zalloc_shm(shmobj, sizeof(struct lttng_ust_lib_ring_buffer)));
		buf = shmp(handle, chanb->buf[0].shmp);
		if (!buf)
			goto end;
		set_shmp(buf->self, chanb->buf[0].shmp._ref);
		ret = lib_ring_buffer_create(buf, chanb, -1,
					handle, shmobj);
		if (ret)
			goto free_bufs;
	}
	chanb->start_tsc = config->cb.ring_buffer_clock_read(chan);

	return 0;

free_bufs:
	/* We only free the buffer data upon shm teardown */
end:
	return -ENOMEM;
}

/**
 * channel_backend_free - destroy the channel
 * @chan: the channel
 *
 * Destroy all channel buffers and frees the channel.
 */
void channel_backend_free(struct channel_backend *chanb,
			  struct lttng_ust_shm_handle *handle)
{
	/* SHM teardown takes care of everything */
}

/**
 * lib_ring_buffer_read - read data from ring_buffer_buffer.
 * @bufb : buffer backend
 * @offset : offset within the buffer
 * @dest : destination address
 * @len : length to copy to destination
 *
 * Should be protected by get_subbuf/put_subbuf.
 * Returns the length copied.
 */
size_t lib_ring_buffer_read(struct lttng_ust_lib_ring_buffer_backend *bufb, size_t offset,
			    void *dest, size_t len, struct lttng_ust_shm_handle *handle)
{
	struct channel_backend *chanb;
	const struct lttng_ust_lib_ring_buffer_config *config;
	ssize_t orig_len;
	struct lttng_ust_lib_ring_buffer_backend_pages_shmp *rpages;
	struct lttng_ust_lib_ring_buffer_backend_pages *backend_pages;
	unsigned long sb_bindex, id;
	void *src;

	chanb = &shmp(handle, bufb->chan)->backend;
	if (!chanb)
		return 0;
	config = &chanb->config;
	orig_len = len;
	offset &= chanb->buf_size - 1;

	if (caa_unlikely(!len))
		return 0;
	id = bufb->buf_rsb.id;
	sb_bindex = subbuffer_id_get_index(config, id);
	rpages = shmp_index(handle, bufb->array, sb_bindex);
	if (!rpages)
		return 0;
	/*
	 * Underlying layer should never ask for reads across
	 * subbuffers.
	 */
	CHAN_WARN_ON(chanb, offset >= chanb->buf_size);
	CHAN_WARN_ON(chanb, config->mode == RING_BUFFER_OVERWRITE
		     && subbuffer_id_is_noref(config, id));
	backend_pages = shmp(handle, rpages->shmp);
	if (!backend_pages)
		return 0;
	src = shmp_index(handle, backend_pages->p, offset & (chanb->subbuf_size - 1));
	if (caa_unlikely(!src))
		return 0;
	memcpy(dest, src, len);
	return orig_len;
}

/**
 * lib_ring_buffer_read_cstr - read a C-style string from ring_buffer.
 * @bufb : buffer backend
 * @offset : offset within the buffer
 * @dest : destination address
 * @len : destination's length
 *
 * Return string's length, or -EINVAL on error.
 * Should be protected by get_subbuf/put_subbuf.
 * Destination length should be at least 1 to hold '\0'.
 */
int lib_ring_buffer_read_cstr(struct lttng_ust_lib_ring_buffer_backend *bufb, size_t offset,
			      void *dest, size_t len, struct lttng_ust_shm_handle *handle)
{
	struct channel_backend *chanb;
	const struct lttng_ust_lib_ring_buffer_config *config;
	ssize_t string_len, orig_offset;
	char *str;
	struct lttng_ust_lib_ring_buffer_backend_pages_shmp *rpages;
	struct lttng_ust_lib_ring_buffer_backend_pages *backend_pages;
	unsigned long sb_bindex, id;

	chanb = &shmp(handle, bufb->chan)->backend;
	if (!chanb)
		return -EINVAL;
	config = &chanb->config;
	if (caa_unlikely(!len))
		return -EINVAL;
	offset &= chanb->buf_size - 1;
	orig_offset = offset;
	id = bufb->buf_rsb.id;
	sb_bindex = subbuffer_id_get_index(config, id);
	rpages = shmp_index(handle, bufb->array, sb_bindex);
	if (!rpages)
		return -EINVAL;
	/*
	 * Underlying layer should never ask for reads across
	 * subbuffers.
	 */
	CHAN_WARN_ON(chanb, offset >= chanb->buf_size);
	CHAN_WARN_ON(chanb, config->mode == RING_BUFFER_OVERWRITE
		     && subbuffer_id_is_noref(config, id));
	backend_pages = shmp(handle, rpages->shmp);
	if (!backend_pages)
		return -EINVAL;
	str = shmp_index(handle, backend_pages->p, offset & (chanb->subbuf_size - 1));
	if (caa_unlikely(!str))
		return -EINVAL;
	string_len = strnlen(str, len);
	if (dest && len) {
		memcpy(dest, str, string_len);
		((char *)dest)[0] = 0;
	}
	return offset - orig_offset;
}

/**
 * lib_ring_buffer_read_offset_address - get address of a buffer location
 * @bufb : buffer backend
 * @offset : offset within the buffer.
 *
 * Return the address where a given offset is located (for read).
 * Should be used to get the current subbuffer header pointer. Given we know
 * it's never on a page boundary, it's safe to read/write directly
 * from/to this address, as long as the read/write is never bigger than
 * a page size.
 */
void *lib_ring_buffer_read_offset_address(struct lttng_ust_lib_ring_buffer_backend *bufb,
					  size_t offset,
					  struct lttng_ust_shm_handle *handle)
{
	struct lttng_ust_lib_ring_buffer_backend_pages_shmp *rpages;
	struct lttng_ust_lib_ring_buffer_backend_pages *backend_pages;
	struct channel_backend *chanb;
	const struct lttng_ust_lib_ring_buffer_config *config;
	unsigned long sb_bindex, id;

	chanb = &shmp(handle, bufb->chan)->backend;
	if (!chanb)
		return NULL;
	config = &chanb->config;
	offset &= chanb->buf_size - 1;
	id = bufb->buf_rsb.id;
	sb_bindex = subbuffer_id_get_index(config, id);
	rpages = shmp_index(handle, bufb->array, sb_bindex);
	if (!rpages)
		return NULL;
	CHAN_WARN_ON(chanb, config->mode == RING_BUFFER_OVERWRITE
		     && subbuffer_id_is_noref(config, id));
	backend_pages = shmp(handle, rpages->shmp);
	if (!backend_pages)
		return NULL;
	return shmp_index(handle, backend_pages->p, offset & (chanb->subbuf_size - 1));
}

/**
 * lib_ring_buffer_offset_address - get address of a location within the buffer
 * @bufb : buffer backend
 * @offset : offset within the buffer.
 *
 * Return the address where a given offset is located.
 * Should be used to get the current subbuffer header pointer. Given we know
 * it's always at the beginning of a page, it's safe to write directly to this
 * address, as long as the write is never bigger than a page size.
 */
void *lib_ring_buffer_offset_address(struct lttng_ust_lib_ring_buffer_backend *bufb,
				     size_t offset,
				     struct lttng_ust_shm_handle *handle)
{
	size_t sbidx;
	struct lttng_ust_lib_ring_buffer_backend_pages_shmp *rpages;
	struct lttng_ust_lib_ring_buffer_backend_pages *backend_pages;
	struct channel_backend *chanb;
	const struct lttng_ust_lib_ring_buffer_config *config;
	unsigned long sb_bindex, id;
	struct lttng_ust_lib_ring_buffer_backend_subbuffer *sb;

	chanb = &shmp(handle, bufb->chan)->backend;
	if (!chanb)
		return NULL;
	config = &chanb->config;
	offset &= chanb->buf_size - 1;
	sbidx = offset >> chanb->subbuf_size_order;
	sb = shmp_index(handle, bufb->buf_wsb, sbidx);
	if (!sb)
		return NULL;
	id = sb->id;
	sb_bindex = subbuffer_id_get_index(config, id);
	rpages = shmp_index(handle, bufb->array, sb_bindex);
	if (!rpages)
		return NULL;
	CHAN_WARN_ON(chanb, config->mode == RING_BUFFER_OVERWRITE
		     && subbuffer_id_is_noref(config, id));
	backend_pages = shmp(handle, rpages->shmp);
	if (!backend_pages)
		return NULL;
	return shmp_index(handle, backend_pages->p, offset & (chanb->subbuf_size - 1));
}
