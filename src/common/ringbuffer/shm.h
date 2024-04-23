/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _LIBRINGBUFFER_SHM_H
#define _LIBRINGBUFFER_SHM_H

#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include "common/logging.h"
#include <urcu/compiler.h>
#include "shm_types.h"

/* channel_handle_create - for UST. */
extern
struct lttng_ust_shm_handle *channel_handle_create(void *data,
				uint64_t memory_map_size, int wakeup_fd)
	__attribute__((visibility("hidden")));

/* channel_handle_add_stream - for UST. */
extern
int channel_handle_add_stream(struct lttng_ust_shm_handle *handle,
		int shm_fd, int wakeup_fd, uint32_t stream_nr,
		uint64_t memory_map_size)
	__attribute__((visibility("hidden")));

unsigned int channel_handle_get_nr_streams(struct lttng_ust_shm_handle *handle)
	__attribute__((visibility("hidden")));

/*
 * Pointer dereferencing. We don't trust the shm_ref, so we validate
 * both the index and offset with known boundaries.
 *
 * "shmp" and "shmp_index" guarantee that it's safe to use the pointer
 * target type, even in the occurrence of shm_ref modification by an
 * untrusted process having write access to the shm_ref. We return a
 * NULL pointer if the ranges are invalid.
 */
static inline
char *_shmp_offset(struct shm_object_table *table, struct shm_ref *ref,
		   size_t idx, size_t elem_size)
{
	struct shm_object *obj;
	size_t objindex, ref_offset;

	objindex = (size_t) ref->index;
	if (caa_unlikely(objindex >= table->allocated_len))
		return NULL;
	obj = &table->objects[objindex];
	ref_offset = (size_t) ref->offset;
	ref_offset += idx * elem_size;
	/* Check if part of the element returned would exceed the limits. */
	if (caa_unlikely(ref_offset + elem_size > obj->memory_map_size))
		return NULL;
	return &obj->memory_map[ref_offset];
}

#define shmp_index(handle, ref, index)	\
	((__typeof__((ref)._type)) _shmp_offset((handle)->table, &(ref)._ref, index, sizeof(*((ref)._type))))

#define shmp(handle, ref)	shmp_index(handle, ref, 0)

static inline
void _set_shmp(struct shm_ref *ref, struct shm_ref src)
{
	*ref = src;
}

#define set_shmp(ref, src)	_set_shmp(&(ref)._ref, src)

struct shm_object_table *shm_object_table_create(size_t max_nb_obj, bool populate)
	__attribute__((visibility("hidden")));

struct shm_object *shm_object_table_alloc(struct shm_object_table *table,
			size_t memory_map_size,
			enum shm_object_type type,
			const int stream_fd,
			int cpu, bool populate)
	__attribute__((visibility("hidden")));

struct shm_object *shm_object_table_append_shm(struct shm_object_table *table,
			int shm_fd, int wakeup_fd, uint32_t stream_nr,
			size_t memory_map_size, bool populate)
	__attribute__((visibility("hidden")));

/* mem ownership is passed to shm_object_table_append_mem(). */
struct shm_object *shm_object_table_append_mem(struct shm_object_table *table,
			void *mem, size_t memory_map_size, int wakeup_fd)
	__attribute__((visibility("hidden")));

void shm_object_table_destroy(struct shm_object_table *table, int consumer)
	__attribute__((visibility("hidden")));

/*
 * zalloc_shm - allocate memory within a shm object.
 *
 * Shared memory is already zeroed by shmget.
 * *NOT* multithread-safe (should be protected by mutex).
 * Returns a -1, -1 tuple on error.
 */
struct shm_ref zalloc_shm(struct shm_object *obj, size_t len)
	__attribute__((visibility("hidden")));

void align_shm(struct shm_object *obj, size_t align)
	__attribute__((visibility("hidden")));

static inline
int shm_get_wait_fd(struct lttng_ust_shm_handle *handle, struct shm_ref *ref)
{
	struct shm_object_table *table = handle->table;
	struct shm_object *obj;
	size_t index;

	index = (size_t) ref->index;
	if (caa_unlikely(index >= table->allocated_len))
		return -EPERM;
	obj = &table->objects[index];
	return obj->wait_fd[0];
}

static inline
int shm_get_wakeup_fd(struct lttng_ust_shm_handle *handle, struct shm_ref *ref)
{
	struct shm_object_table *table = handle->table;
	struct shm_object *obj;
	size_t index;

	index = (size_t) ref->index;
	if (caa_unlikely(index >= table->allocated_len))
		return -EPERM;
	obj = &table->objects[index];
	return obj->wait_fd[1];
}

static inline
int shm_close_wait_fd(struct lttng_ust_shm_handle *handle,
		struct shm_ref *ref)
{
	struct shm_object_table *table = handle->table;
	struct shm_object *obj;
	int wait_fd;
	size_t index;
	int ret;

	index = (size_t) ref->index;
	if (caa_unlikely(index >= table->allocated_len))
		return -EPERM;
	obj = &table->objects[index];
	wait_fd = obj->wait_fd[0];
	if (wait_fd < 0)
		return -ENOENT;
	obj->wait_fd[0] = -1;
	ret = close(wait_fd);
	if (ret) {
		ret = -errno;
		return ret;
	}
	return 0;
}

static inline
int shm_close_wakeup_fd(struct lttng_ust_shm_handle *handle,
		struct shm_ref *ref)
{
	struct shm_object_table *table = handle->table;
	struct shm_object *obj;
	int wakeup_fd;
	size_t index;
	int ret;

	index = (size_t) ref->index;
	if (caa_unlikely(index >= table->allocated_len))
		return -EPERM;
	obj = &table->objects[index];
	wakeup_fd = obj->wait_fd[1];
	if (wakeup_fd < 0)
		return -ENOENT;
	obj->wait_fd[1] = -1;
	ret = close(wakeup_fd);
	if (ret) {
		ret = -errno;
		return ret;
	}
	return 0;
}

static inline
int shm_get_shm_fd(struct lttng_ust_shm_handle *handle, struct shm_ref *ref)
{
	struct shm_object_table *table = handle->table;
	struct shm_object *obj;
	size_t index;

	index = (size_t) ref->index;
	if (caa_unlikely(index >= table->allocated_len))
		return -EPERM;
	obj = &table->objects[index];
	return obj->shm_fd;
}


static inline
int shm_get_shm_size(struct lttng_ust_shm_handle *handle, struct shm_ref *ref,
		uint64_t *size)
{
	struct shm_object_table *table = handle->table;
	struct shm_object *obj;
	size_t index;

	index = (size_t) ref->index;
	if (caa_unlikely(index >= table->allocated_len))
		return -EPERM;
	obj = &table->objects[index];
	*size = obj->memory_map_size;
	return 0;
}

#endif /* _LIBRINGBUFFER_SHM_H */
