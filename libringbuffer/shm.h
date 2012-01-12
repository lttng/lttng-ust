#ifndef _LIBRINGBUFFER_SHM_H
#define _LIBRINGBUFFER_SHM_H

/*
 * libringbuffer/shm.h
 *
 * Copyright 2011 (c) - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Dual LGPL v2.1/GPL v2 license.
 */

#include <stdint.h>
#include <usterr-signal-safe.h>
#include <urcu/compiler.h>
#include "shm_types.h"

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

#define shmp_index(handle, ref, index)					\
	({								\
		__typeof__((ref)._type) ____ptr_ret;			\
		____ptr_ret = (__typeof__(____ptr_ret)) _shmp_offset((handle)->table, &(ref)._ref, index, sizeof(*____ptr_ret));	\
		____ptr_ret;						\
	})

#define shmp(handle, ref)	shmp_index(handle, ref, 0)

static inline
void _set_shmp(struct shm_ref *ref, struct shm_ref src)
{
	*ref = src;
}

#define set_shmp(ref, src)	_set_shmp(&(ref)._ref, src)

struct shm_object_table *shm_object_table_create(size_t max_nb_obj);
struct shm_object *shm_object_table_append_shadow(struct shm_object_table *table,
			int shm_fd, int wait_fd, size_t memory_map_size);
void shm_object_table_destroy(struct shm_object_table *table);
struct shm_object *shm_object_table_append(struct shm_object_table *table,
					   size_t memory_map_size);

/*
 * zalloc_shm - allocate memory within a shm object.
 *
 * Shared memory is already zeroed by shmget.
 * *NOT* multithread-safe (should be protected by mutex).
 * Returns a -1, -1 tuple on error.
 */
struct shm_ref zalloc_shm(struct shm_object *obj, size_t len);
void align_shm(struct shm_object *obj, size_t align);

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
int shm_get_object_data(struct lttng_ust_shm_handle *handle, struct shm_ref *ref,
		int **shm_fd, int **wait_fd, uint64_t **memory_map_size)
{
	struct shm_object_table *table = handle->table;
	struct shm_object *obj;
	size_t index;

	index = (size_t) ref->index;
	if (caa_unlikely(index >= table->allocated_len))
		return -EPERM;
	obj = &table->objects[index];
	*shm_fd = &obj->shm_fd;
	*wait_fd = &obj->wait_fd[0];
	*memory_map_size = &obj->allocated_len;
	return 0;
}

#endif /* _LIBRINGBUFFER_SHM_H */
