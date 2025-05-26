/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2005-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#define _LGPL_SOURCE
#include "shm.h"
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>	/* For mode constants */
#include <fcntl.h>	/* For O_* constants */
#include <assert.h>
#include <stdio.h>
#include <signal.h>
#include <dirent.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef HAVE_LIBNUMA
#include <numa.h>
#include <numaif.h>
#endif

#include <lttng/ust-utils.h>
#include <lttng/ust-fd.h>

#include "common/macros.h"
#include "common/compat/mmap.h"

/*
 * Ensure we have the required amount of space available by writing 0
 * into the entire buffer. Not doing so can trigger SIGBUS when going
 * beyond the available shm space.
 */
static
int zero_file(int fd, size_t len)
{
	ssize_t retlen;
	size_t written = 0;
	char *zeropage;
	long pagelen;
	int ret;

	pagelen = sysconf(_SC_PAGESIZE);
	if (pagelen < 0)
		return (int) pagelen;
	zeropage = calloc(pagelen, 1);
	if (!zeropage)
		return -ENOMEM;

	while (len > written) {
		do {
			retlen = write(fd, zeropage,
				min_t(size_t, pagelen, len - written));
		} while (retlen == -1UL && errno == EINTR);
		if (retlen < 0) {
			ret = (int) retlen;
			goto error;
		}
		written += retlen;
	}
	ret = 0;
error:
	free(zeropage);
	return ret;
}

struct lttng_counter_shm_object_table *lttng_counter_shm_object_table_create(size_t max_nb_obj, bool populate)
{
	struct lttng_counter_shm_object_table *table;

	table = zmalloc_populate(sizeof(struct lttng_counter_shm_object_table) +
			max_nb_obj * sizeof(table->objects[0]), populate);
	if (!table)
		return NULL;
	table->size = max_nb_obj;
	return table;
}

static
struct lttng_counter_shm_object *_lttng_counter_shm_object_table_alloc_shm(struct lttng_counter_shm_object_table *table,
					   size_t memory_map_size,
					   int cpu_fd, bool populate)
{
	struct lttng_counter_shm_object *obj;
	int flags = MAP_SHARED;
	int shmfd, ret;
	char *memory_map;

	if (cpu_fd < 0)
		return NULL;
	if (table->allocated_len >= table->size)
		return NULL;
	obj = &table->objects[table->allocated_len];

	/* create shm */

	shmfd = cpu_fd;
	ret = zero_file(shmfd, memory_map_size);
	if (ret) {
		PERROR("zero_file");
		goto error_zero_file;
	}
	ret = ftruncate(shmfd, memory_map_size);
	if (ret) {
		PERROR("ftruncate");
		goto error_ftruncate;
	}
	/*
	 * Also ensure the file metadata is synced with the storage by using
	 * fsync(2).
	 */
	ret = fsync(shmfd);
	if (ret) {
		PERROR("fsync");
		goto error_fsync;
	}
	obj->shm_fd_ownership = 0;
	obj->shm_fd = shmfd;

	if (populate)
		flags |= LTTNG_MAP_POPULATE;
	/* memory_map: mmap */
	memory_map = mmap(NULL, memory_map_size, PROT_READ | PROT_WRITE,
			  flags, shmfd, 0);
	if (memory_map == MAP_FAILED) {
		PERROR("mmap");
		goto error_mmap;
	}
	obj->type = LTTNG_COUNTER_SHM_OBJECT_SHM;
	obj->memory_map = memory_map;
	obj->memory_map_size = memory_map_size;
	obj->allocated_len = 0;
	obj->index = table->allocated_len++;

	return obj;

error_mmap:
error_fsync:
error_ftruncate:
error_zero_file:
	return NULL;
}

static
struct lttng_counter_shm_object *_lttng_counter_shm_object_table_alloc_mem(struct lttng_counter_shm_object_table *table,
					   size_t memory_map_size, bool populate)
{
	struct lttng_counter_shm_object *obj;
	void *memory_map;

	if (table->allocated_len >= table->size)
		return NULL;
	obj = &table->objects[table->allocated_len];

	memory_map = zmalloc_populate(memory_map_size, populate);
	if (!memory_map)
		goto alloc_error;

	/* no shm_fd */
	obj->shm_fd = -1;
	obj->shm_fd_ownership = 0;

	obj->type = LTTNG_COUNTER_SHM_OBJECT_MEM;
	obj->memory_map = memory_map;
	obj->memory_map_size = memory_map_size;
	obj->allocated_len = 0;
	obj->index = table->allocated_len++;

	return obj;

alloc_error:
	return NULL;
}

/*
 * libnuma prints errors on the console even for numa_available().
 * Work-around this limitation by using get_mempolicy() directly to
 * check whether the kernel supports mempolicy.
 */
#ifdef HAVE_LIBNUMA
static bool lttng_is_numa_available(void)
{
	int ret;

	ret = get_mempolicy(NULL, NULL, 0, NULL, 0);
	if (ret && (errno == ENOSYS || errno == EPERM)) {
		return false;
	}
	return numa_available() >= 0;
}
#endif

#ifdef HAVE_LIBNUMA
struct lttng_counter_shm_object *lttng_counter_shm_object_table_alloc(struct lttng_counter_shm_object_table *table,
			size_t memory_map_size,
			enum lttng_counter_shm_object_type type,
			int cpu_fd,
			int cpu,
			bool populate)
#else
struct lttng_counter_shm_object *lttng_counter_shm_object_table_alloc(struct lttng_counter_shm_object_table *table,
			size_t memory_map_size,
			enum lttng_counter_shm_object_type type,
			int cpu_fd,
			int cpu __attribute__((unused)),
			bool populate)
#endif
{
	struct lttng_counter_shm_object *shm_object;
#ifdef HAVE_LIBNUMA
	int oldnode = 0, node;
	bool numa_avail;

	numa_avail = lttng_is_numa_available();
	if (numa_avail) {
		oldnode = numa_preferred();
		if (cpu >= 0) {
			node = numa_node_of_cpu(cpu);
			if (node >= 0)
				numa_set_preferred(node);
		}
		if (cpu < 0 || node < 0)
			numa_set_localalloc();
	}
#endif /* HAVE_LIBNUMA */
	switch (type) {
	case LTTNG_COUNTER_SHM_OBJECT_SHM:
		shm_object = _lttng_counter_shm_object_table_alloc_shm(table, memory_map_size,
				cpu_fd, populate);
		break;
	case LTTNG_COUNTER_SHM_OBJECT_MEM:
		shm_object = _lttng_counter_shm_object_table_alloc_mem(table, memory_map_size,
				populate);
		break;
	default:
		assert(0);
	}
#ifdef HAVE_LIBNUMA
	if (numa_avail)
		numa_set_preferred(oldnode);
#endif /* HAVE_LIBNUMA */
	return shm_object;
}

struct lttng_counter_shm_object *lttng_counter_shm_object_table_append_shm(struct lttng_counter_shm_object_table *table,
			int shm_fd, size_t memory_map_size, bool populate)
{
	struct lttng_counter_shm_object *obj;
	int flags = MAP_SHARED;
	char *memory_map;

	if (table->allocated_len >= table->size)
		return NULL;

	obj = &table->objects[table->allocated_len];

	obj->shm_fd = shm_fd;
	obj->shm_fd_ownership = 1;

	if (populate)
		flags |= LTTNG_MAP_POPULATE;
	/* memory_map: mmap */
	memory_map = mmap(NULL, memory_map_size, PROT_READ | PROT_WRITE,
			  flags, shm_fd, 0);
	if (memory_map == MAP_FAILED) {
		PERROR("mmap");
		goto error_mmap;
	}
	obj->type = LTTNG_COUNTER_SHM_OBJECT_SHM;
	obj->memory_map = memory_map;
	obj->memory_map_size = memory_map_size;
	obj->allocated_len = memory_map_size;
	obj->index = table->allocated_len++;

	return obj;

error_mmap:
	return NULL;
}

/*
 * Passing ownership of mem to object.
 */
struct lttng_counter_shm_object *lttng_counter_shm_object_table_append_mem(struct lttng_counter_shm_object_table *table,
			void *mem, size_t memory_map_size)
{
	struct lttng_counter_shm_object *obj;

	if (table->allocated_len >= table->size)
		return NULL;
	obj = &table->objects[table->allocated_len];

	obj->shm_fd = -1;
	obj->shm_fd_ownership = 0;

	obj->type = LTTNG_COUNTER_SHM_OBJECT_MEM;
	obj->memory_map = mem;
	obj->memory_map_size = memory_map_size;
	obj->allocated_len = memory_map_size;
	obj->index = table->allocated_len++;

	return obj;

	return NULL;
}

static
void lttng_counter_shmp_object_destroy(struct lttng_counter_shm_object *obj, int consumer)
{
	switch (obj->type) {
	case LTTNG_COUNTER_SHM_OBJECT_SHM:
	{
		int ret;

		ret = munmap(obj->memory_map, obj->memory_map_size);
		if (ret) {
			PERROR("umnmap");
			assert(0);
		}

		if (obj->shm_fd_ownership) {
			/* Delete FDs only if called from app (not consumer). */
			if (!consumer) {
				lttng_ust_lock_fd_tracker();
				ret = close(obj->shm_fd);
				if (!ret) {
					lttng_ust_delete_fd_from_tracker(obj->shm_fd);
				} else {
					PERROR("close");
					assert(0);
				}
				lttng_ust_unlock_fd_tracker();
			} else {
				ret = close(obj->shm_fd);
				if (ret) {
					PERROR("close");
					assert(0);
				}
			}
		}
		break;
	}
	case LTTNG_COUNTER_SHM_OBJECT_MEM:
	{
		free(obj->memory_map);
		break;
	}
	default:
		assert(0);
	}
}

void lttng_counter_shm_object_table_destroy(struct lttng_counter_shm_object_table *table, int consumer)
{
	int i;

	for (i = 0; i < table->allocated_len; i++)
		lttng_counter_shmp_object_destroy(&table->objects[i], consumer);
	free(table);
}

/*
 * lttng_counter_zalloc_shm - allocate memory within a shm object.
 *
 * Shared memory is already zeroed by shmget.
 * *NOT* multithread-safe (should be protected by mutex).
 * Returns a -1, -1 tuple on error.
 */
struct lttng_counter_shm_ref lttng_counter_zalloc_shm(struct lttng_counter_shm_object *obj, size_t len)
{
	struct lttng_counter_shm_ref ref;
	struct lttng_counter_shm_ref shm_ref_error = { -1, -1 };

	if (obj->memory_map_size - obj->allocated_len < len)
		return shm_ref_error;
	ref.index = obj->index;
	ref.offset =  obj->allocated_len;
	obj->allocated_len += len;
	return ref;
}

void lttng_counter_align_shm(struct lttng_counter_shm_object *obj, size_t align)
{
	size_t offset_len = lttng_ust_offset_align(obj->allocated_len, align);
	obj->allocated_len += offset_len;
}
