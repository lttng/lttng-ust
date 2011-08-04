/*
 * ring_buffer_backend.c
 *
 * Copyright (C) 2005-2010 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Dual LGPL v2.1/GPL v2 license.
 */

#include <urcu/arch.h>

#include "ust/core.h"

#include "config.h"
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
int lib_ring_buffer_backend_allocate(const struct lib_ring_buffer_config *config,
				     struct lib_ring_buffer_backend *bufb,
				     size_t size, size_t num_subbuf,
				     int extra_reader_sb,
				     struct shm_header *shm_header)
{
	struct channel_backend *chanb = &shmp(bufb->chan)->backend;
	unsigned long subbuf_size, mmap_offset = 0;
	unsigned long num_subbuf_alloc;
	unsigned long i;

	subbuf_size = chanb->subbuf_size;
	num_subbuf_alloc = num_subbuf;

	if (extra_reader_sb)
		num_subbuf_alloc++;

	/* Align the entire buffer backend data on PAGE_SIZE */
	align_shm(shm_header, PAGE_SIZE);
	set_shmp(bufb->array, zalloc_shm(shm_header,
			sizeof(*bufb->array) * num_subbuf_alloc));
	if (unlikely(!shmp(bufb->array)))
		goto array_error;

	/*
	 * This is the largest element (the buffer pages) which needs to
	 * be aligned on PAGE_SIZE.
	 */
	align_shm(shm_header, PAGE_SIZE);
	set_shmp(bufb->memory_map, zalloc_shm(shm_header,
			subbuf_size * num_subbuf_alloc));
	if (unlikely(!shmp(bufb->memory_map)))
		goto memory_map_error;

	/* Allocate backend pages array elements */
	for (i = 0; i < num_subbuf_alloc; i++) {
		align_shm(shm_header, __alignof__(struct lib_ring_buffer_backend_pages));
		set_shmp(bufb->array[i],
			zalloc_shm(shm_header,
				sizeof(struct lib_ring_buffer_backend_pages)));
		if (!shmp(bufb->array[i]))
			goto free_array;
	}

	/* Allocate write-side subbuffer table */
	align_shm(shm_header, __alignof__(struct lib_ring_buffer_backend_subbuffer));
	bufb->buf_wsb = zalloc_shm(shm_header,
				sizeof(struct lib_ring_buffer_backend_subbuffer)
				* num_subbuf);
	if (unlikely(!shmp(bufb->buf_wsb)))
		goto free_array;

	for (i = 0; i < num_subbuf; i++)
		shmp(bufb->buf_wsb)[i].id = subbuffer_id(config, 0, 1, i);

	/* Assign read-side subbuffer table */
	if (extra_reader_sb)
		bufb->buf_rsb.id = subbuffer_id(config, 0, 1,
						num_subbuf_alloc - 1);
	else
		bufb->buf_rsb.id = subbuffer_id(config, 0, 1, 0);

	/* Assign pages to page index */
	for (i = 0; i < num_subbuf_alloc; i++) {
		set_shmp(shmp(bufb->array)[i]->p,
			 &shmp(bufb->memory_map)[i * subbuf_size]);
		if (config->output == RING_BUFFER_MMAP) {
			shmp(bufb->array)[i]->mmap_offset = mmap_offset;
			mmap_offset += subbuf_size;
		}
	}
	/*
	 * Align the end of each buffer backend data on PAGE_SIZE, to
	 * behave like an array which contains elements that need to be
	 * aligned on PAGE_SIZE.
	 */
	align_shm(shm_header, PAGE_SIZE);

	return 0;

free_array:
	/* bufb->array[i] will be freed by shm teardown */
memory_map_error:
	/* bufb->array will be freed by shm teardown */
array_error:
	return -ENOMEM;
}

int lib_ring_buffer_backend_create(struct lib_ring_buffer_backend *bufb,
				   struct channel_backend *chanb, int cpu,
				   struct shm_header *shm_header)
{
	const struct lib_ring_buffer_config *config = chanb->config;

	set_shmp(&bufb->chan, caa_container_of(chanb, struct channel, backend));
	bufb->cpu = cpu;

	return lib_ring_buffer_backend_allocate(config, bufb, chanb->buf_size,
						chanb->num_subbuf,
						chanb->extra_reader_sb,
						shm_header);
}

void lib_ring_buffer_backend_free(struct lib_ring_buffer_backend *bufb)
{
	/* bufb->buf_wsb will be freed by shm teardown */
	/* bufb->array[i] will be freed by shm teardown */
	/* bufb->array will be freed by shm teardown */
	bufb->allocated = 0;
}

void lib_ring_buffer_backend_reset(struct lib_ring_buffer_backend *bufb)
{
	struct channel_backend *chanb = &shmp(bufb->chan)->backend;
	const struct lib_ring_buffer_config *config = chanb->config;
	unsigned long num_subbuf_alloc;
	unsigned int i;

	num_subbuf_alloc = chanb->num_subbuf;
	if (chanb->extra_reader_sb)
		num_subbuf_alloc++;

	for (i = 0; i < chanb->num_subbuf; i++)
		shmp(bufb->buf_wsb)[i].id = subbuffer_id(config, 0, 1, i);
	if (chanb->extra_reader_sb)
		bufb->buf_rsb.id = subbuffer_id(config, 0, 1,
						num_subbuf_alloc - 1);
	else
		bufb->buf_rsb.id = subbuffer_id(config, 0, 1, 0);

	for (i = 0; i < num_subbuf_alloc; i++) {
		/* Don't reset mmap_offset */
		v_set(config, &shmp(bufb->array)[i]->records_commit, 0);
		v_set(config, &shmp(bufb->array)[i]->records_unread, 0);
		shmp(bufb->array)[i]->data_size = 0;
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
	const struct lib_ring_buffer_config *config = chanb->config;

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
 * @priv: client private data
 * @parent: dentry of parent directory, %NULL for root directory
 * @subbuf_size: size of sub-buffers (> PAGE_SIZE, power of 2)
 * @num_subbuf: number of sub-buffers (power of 2)
 * @shm_header: shared memory header
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
			 const struct lib_ring_buffer_config *config,
			 void *priv, size_t subbuf_size, size_t num_subbuf,
			 struct shm_header *shm_header)
{
	struct channel *chan = caa_container_of(chanb, struct channel, backend);
	unsigned int i;
	int ret;

	if (!name)
		return -EPERM;

	if (!(subbuf_size && num_subbuf))
		return -EPERM;

	/* Check that the subbuffer size is larger than a page. */
	if (subbuf_size < PAGE_SIZE)
		return -EINVAL;

	/*
	 * Make sure the number of subbuffers and subbuffer size are power of 2.
	 */
	CHAN_WARN_ON(chanb, hweight32(subbuf_size) != 1);
	CHAN_WARN_ON(chanb, hweight32(num_subbuf) != 1);

	ret = subbuffer_id_check_index(config, num_subbuf);
	if (ret)
		return ret;

	chanb->priv = priv;
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
	chanb->config = config;

	if (config->alloc == RING_BUFFER_ALLOC_PER_CPU) {
		struct lib_ring_buffer *buf;
		size_t alloc_size;

		/* Allocating the buffer per-cpu structures */
		align_shm(shm_header, __alignof__(struct lib_ring_buffer));
		alloc_size = sizeof(struct lib_ring_buffer);
		buf = zalloc_shm(shm_header, alloc_size * num_possible_cpus());
		if (!buf)
			goto end;
		set_shmp(chanb->buf, buf);

		/*
		 * We need to allocate for all possible cpus.
		 */
		for_each_possible_cpu(i) {
			ret = lib_ring_buffer_create(&shmp(chanb->buf)[i],
						     chanb, i, shm_header);
			if (ret)
				goto free_bufs;	/* cpu hotplug locked */
		}
	} else {
		struct lib_ring_buffer *buf;
		size_t alloc_size;

		align_shm(shm_header, __alignof__(struct lib_ring_buffer));
		alloc_size = sizeof(struct lib_ring_buffer);
		buf = zalloc_shm(shm_header, alloc_size);
		if (!buf)
			goto end;
		set_shmp(chanb->buf, buf);
		ret = lib_ring_buffer_create(shmp(chanb->buf), chanb, -1,
					     shm_header);
		if (ret)
			goto free_bufs;
	}
	chanb->start_tsc = config->cb.ring_buffer_clock_read(chan);

	return 0;

free_bufs:
	if (config->alloc == RING_BUFFER_ALLOC_PER_CPU) {
		for_each_possible_cpu(i) {
			struct lib_ring_buffer *buf = &shmp(chanb->buf)[i];

			if (!buf->backend.allocated)
				continue;
			lib_ring_buffer_free(buf);
		}
	}
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
void channel_backend_free(struct channel_backend *chanb)
{
	const struct lib_ring_buffer_config *config = chanb->config;
	unsigned int i;

	if (config->alloc == RING_BUFFER_ALLOC_PER_CPU) {
		for_each_possible_cpu(i) {
			struct lib_ring_buffer *buf = &shmp(chanb->buf)[i];

			if (!buf->backend.allocated)
				continue;
			lib_ring_buffer_free(buf);
		}
	} else {
		struct lib_ring_buffer *buf = shmp(chanb->buf);

		CHAN_WARN_ON(chanb, !buf->backend.allocated);
		lib_ring_buffer_free(buf);
	}
	/* We only free the buffer data upon shm teardown */
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
size_t lib_ring_buffer_read(struct lib_ring_buffer_backend *bufb, size_t offset,
			    void *dest, size_t len)
{
	struct channel_backend *chanb = &shmp(bufb->chan)->backend;
	const struct lib_ring_buffer_config *config = chanb->config;
	ssize_t orig_len;
	struct lib_ring_buffer_backend_pages *rpages;
	unsigned long sb_bindex, id;

	orig_len = len;
	offset &= chanb->buf_size - 1;

	if (unlikely(!len))
		return 0;
	id = bufb->buf_rsb.id;
	sb_bindex = subbuffer_id_get_index(config, id);
	rpages = shmp(bufb->array)[sb_bindex];
	/*
	 * Underlying layer should never ask for reads across
	 * subbuffers.
	 */
	CHAN_WARN_ON(chanb, offset >= chanb->buf_size);
	CHAN_WARN_ON(chanb, config->mode == RING_BUFFER_OVERWRITE
		     && subbuffer_id_is_noref(config, id));
	memcpy(dest, shmp(rpages->p) + (offset & ~(chanb->subbuf_size - 1)), len);
	return orig_len;
}

/**
 * lib_ring_buffer_read_cstr - read a C-style string from ring_buffer.
 * @bufb : buffer backend
 * @offset : offset within the buffer
 * @dest : destination address
 * @len : destination's length
 *
 * return string's length
 * Should be protected by get_subbuf/put_subbuf.
 */
int lib_ring_buffer_read_cstr(struct lib_ring_buffer_backend *bufb, size_t offset,
			      void *dest, size_t len)
{
	struct channel_backend *chanb = &shmp(bufb->chan)->backend;
	const struct lib_ring_buffer_config *config = chanb->config;
	ssize_t string_len, orig_offset;
	char *str;
	struct lib_ring_buffer_backend_pages *rpages;
	unsigned long sb_bindex, id;

	offset &= chanb->buf_size - 1;
	orig_offset = offset;
	id = bufb->buf_rsb.id;
	sb_bindex = subbuffer_id_get_index(config, id);
	rpages = shmp(bufb->array)[sb_bindex];
	/*
	 * Underlying layer should never ask for reads across
	 * subbuffers.
	 */
	CHAN_WARN_ON(chanb, offset >= chanb->buf_size);
	CHAN_WARN_ON(chanb, config->mode == RING_BUFFER_OVERWRITE
		     && subbuffer_id_is_noref(config, id));
	str = (char *)shmp(rpages->p) + (offset & ~(chanb->subbuf_size - 1));
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
 * it's never on a page boundary, it's safe to write directly to this address,
 * as long as the write is never bigger than a page size.
 */
void *lib_ring_buffer_read_offset_address(struct lib_ring_buffer_backend *bufb,
					  size_t offset)
{
	struct lib_ring_buffer_backend_pages *rpages;
	struct channel_backend *chanb = &shmp(bufb->chan)->backend;
	const struct lib_ring_buffer_config *config = chanb->config;
	unsigned long sb_bindex, id;

	offset &= chanb->buf_size - 1;
	id = bufb->buf_rsb.id;
	sb_bindex = subbuffer_id_get_index(config, id);
	rpages = shmp(bufb->array)[sb_bindex];
	CHAN_WARN_ON(chanb, config->mode == RING_BUFFER_OVERWRITE
		     && subbuffer_id_is_noref(config, id));
	return shmp(rpages->p) + (offset & ~(chanb->subbuf_size - 1));
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
void *lib_ring_buffer_offset_address(struct lib_ring_buffer_backend *bufb,
				     size_t offset)
{
	size_t sbidx;
	struct lib_ring_buffer_backend_pages *rpages;
	struct channel_backend *chanb = &shmp(bufb->chan)->backend;
	const struct lib_ring_buffer_config *config = chanb->config;
	unsigned long sb_bindex, id;

	offset &= chanb->buf_size - 1;
	sbidx = offset >> chanb->subbuf_size_order;
	id = shmp(bufb->buf_wsb)[sbidx].id;
	sb_bindex = subbuffer_id_get_index(config, id);
	rpages = shmp(bufb->array)[sb_bindex];
	CHAN_WARN_ON(chanb, config->mode == RING_BUFFER_OVERWRITE
		     && subbuffer_id_is_noref(config, id));
	return shmp(rpages->p) + (offset & ~(chanb->subbuf_size - 1));
}
