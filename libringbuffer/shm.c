/*
 * libringbuffer/shm.c
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

#define _LGPL_SOURCE
#include <config.h>
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
#include <lttng/align.h>
#include <limits.h>
#include <stdbool.h>
#ifdef HAVE_LIBNUMA
#include <numa.h>
#include <numaif.h>
#endif
#include <helper.h>
#include <ust-fd.h>

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

struct shm_object_table *shm_object_table_create(size_t max_nb_obj)
{
	struct shm_object_table *table;

	table = zmalloc(sizeof(struct shm_object_table) +
			max_nb_obj * sizeof(table->objects[0]));
	if (!table)
		return NULL;
	table->size = max_nb_obj;
	return table;
}

static
struct shm_object *_shm_object_table_alloc_shm(struct shm_object_table *table,
					   size_t memory_map_size,
					   int stream_fd)
{
	int shmfd, waitfd[2], ret, i;
	struct shm_object *obj;
	char *memory_map;

	if (stream_fd < 0)
		return NULL;
	if (table->allocated_len >= table->size)
		return NULL;
	obj = &table->objects[table->allocated_len];

	/* wait_fd: create pipe */
	ret = pipe(waitfd);
	if (ret < 0) {
		PERROR("pipe");
		goto error_pipe;
	}
	for (i = 0; i < 2; i++) {
		ret = fcntl(waitfd[i], F_SETFD, FD_CLOEXEC);
		if (ret < 0) {
			PERROR("fcntl");
			goto error_fcntl;
		}
	}
	/* The write end of the pipe needs to be non-blocking */
	ret = fcntl(waitfd[1], F_SETFL, O_NONBLOCK);
	if (ret < 0) {
		PERROR("fcntl");
		goto error_fcntl;
	}
	memcpy(obj->wait_fd, waitfd, sizeof(waitfd));

	/* create shm */

	shmfd = stream_fd;
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

	/* memory_map: mmap */
	memory_map = mmap(NULL, memory_map_size, PROT_READ | PROT_WRITE,
			  MAP_SHARED, shmfd, 0);
	if (memory_map == MAP_FAILED) {
		PERROR("mmap");
		goto error_mmap;
	}
	obj->type = SHM_OBJECT_SHM;
	obj->memory_map = memory_map;
	obj->memory_map_size = memory_map_size;
	obj->allocated_len = 0;
	obj->index = table->allocated_len++;

	return obj;

error_mmap:
error_fsync:
error_ftruncate:
error_zero_file:
error_fcntl:
	for (i = 0; i < 2; i++) {
		ret = close(waitfd[i]);
		if (ret) {
			PERROR("close");
			assert(0);
		}
	}
error_pipe:
	return NULL;
}

static
struct shm_object *_shm_object_table_alloc_mem(struct shm_object_table *table,
					   size_t memory_map_size)
{
	struct shm_object *obj;
	void *memory_map;
	int waitfd[2], i, ret;

	if (table->allocated_len >= table->size)
		return NULL;
	obj = &table->objects[table->allocated_len];

	memory_map = zmalloc(memory_map_size);
	if (!memory_map)
		goto alloc_error;

	/* wait_fd: create pipe */
	ret = pipe(waitfd);
	if (ret < 0) {
		PERROR("pipe");
		goto error_pipe;
	}
	for (i = 0; i < 2; i++) {
		ret = fcntl(waitfd[i], F_SETFD, FD_CLOEXEC);
		if (ret < 0) {
			PERROR("fcntl");
			goto error_fcntl;
		}
	}
	/* The write end of the pipe needs to be non-blocking */
	ret = fcntl(waitfd[1], F_SETFL, O_NONBLOCK);
	if (ret < 0) {
		PERROR("fcntl");
		goto error_fcntl;
	}
	memcpy(obj->wait_fd, waitfd, sizeof(waitfd));

	/* no shm_fd */
	obj->shm_fd = -1;
	obj->shm_fd_ownership = 0;

	obj->type = SHM_OBJECT_MEM;
	obj->memory_map = memory_map;
	obj->memory_map_size = memory_map_size;
	obj->allocated_len = 0;
	obj->index = table->allocated_len++;

	return obj;

error_fcntl:
	for (i = 0; i < 2; i++) {
		ret = close(waitfd[i]);
		if (ret) {
			PERROR("close");
			assert(0);
		}
	}
error_pipe:
	free(memory_map);
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
	if (ret && errno == ENOSYS) {
		return false;
	}
	return numa_available() > 0;
}
#endif

struct shm_object *shm_object_table_alloc(struct shm_object_table *table,
			size_t memory_map_size,
			enum shm_object_type type,
			int stream_fd,
			int cpu)
{
	struct shm_object *shm_object;
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
	case SHM_OBJECT_SHM:
		shm_object = _shm_object_table_alloc_shm(table, memory_map_size,
				stream_fd);
		break;
	case SHM_OBJECT_MEM:
		shm_object = _shm_object_table_alloc_mem(table, memory_map_size);
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

struct shm_object *shm_object_table_append_shm(struct shm_object_table *table,
			int shm_fd, int wakeup_fd, uint32_t stream_nr,
			size_t memory_map_size)
{
	struct shm_object *obj;
	char *memory_map;
	int ret;

	if (table->allocated_len >= table->size)
		return NULL;
	/* streams _must_ be received in sequential order, else fail. */
	if (stream_nr + 1 != table->allocated_len)
		return NULL;

	obj = &table->objects[table->allocated_len];

	/* wait_fd: set write end of the pipe. */
	obj->wait_fd[0] = -1;	/* read end is unset */
	obj->wait_fd[1] = wakeup_fd;
	obj->shm_fd = shm_fd;
	obj->shm_fd_ownership = 1;

	ret = fcntl(obj->wait_fd[1], F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		PERROR("fcntl");
		goto error_fcntl;
	}
	/* The write end of the pipe needs to be non-blocking */
	ret = fcntl(obj->wait_fd[1], F_SETFL, O_NONBLOCK);
	if (ret < 0) {
		PERROR("fcntl");
		goto error_fcntl;
	}

	/* memory_map: mmap */
	memory_map = mmap(NULL, memory_map_size, PROT_READ | PROT_WRITE,
			  MAP_SHARED, shm_fd, 0);
	if (memory_map == MAP_FAILED) {
		PERROR("mmap");
		goto error_mmap;
	}
	obj->type = SHM_OBJECT_SHM;
	obj->memory_map = memory_map;
	obj->memory_map_size = memory_map_size;
	obj->allocated_len = memory_map_size;
	obj->index = table->allocated_len++;

	return obj;

error_fcntl:
error_mmap:
	return NULL;
}

/*
 * Passing ownership of mem to object.
 */
struct shm_object *shm_object_table_append_mem(struct shm_object_table *table,
			void *mem, size_t memory_map_size, int wakeup_fd)
{
	struct shm_object *obj;
	int ret;

	if (table->allocated_len >= table->size)
		return NULL;
	obj = &table->objects[table->allocated_len];

	obj->wait_fd[0] = -1;	/* read end is unset */
	obj->wait_fd[1] = wakeup_fd;
	obj->shm_fd = -1;
	obj->shm_fd_ownership = 0;

	ret = fcntl(obj->wait_fd[1], F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		PERROR("fcntl");
		goto error_fcntl;
	}
	/* The write end of the pipe needs to be non-blocking */
	ret = fcntl(obj->wait_fd[1], F_SETFL, O_NONBLOCK);
	if (ret < 0) {
		PERROR("fcntl");
		goto error_fcntl;
	}

	obj->type = SHM_OBJECT_MEM;
	obj->memory_map = mem;
	obj->memory_map_size = memory_map_size;
	obj->allocated_len = memory_map_size;
	obj->index = table->allocated_len++;

	return obj;

error_fcntl:
	return NULL;
}

static
void shmp_object_destroy(struct shm_object *obj, int consumer)
{
	switch (obj->type) {
	case SHM_OBJECT_SHM:
	{
		int ret, i;

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
		for (i = 0; i < 2; i++) {
			if (obj->wait_fd[i] < 0)
				continue;
			if (!consumer) {
				lttng_ust_lock_fd_tracker();
				ret = close(obj->wait_fd[i]);
				if (!ret) {
					lttng_ust_delete_fd_from_tracker(obj->wait_fd[i]);
				} else {
					PERROR("close");
					assert(0);
				}
				lttng_ust_unlock_fd_tracker();
			} else {
				ret = close(obj->wait_fd[i]);
				if (ret) {
					PERROR("close");
					assert(0);
				}
			}
		}
		break;
	}
	case SHM_OBJECT_MEM:
	{
		int ret, i;

		for (i = 0; i < 2; i++) {
			if (obj->wait_fd[i] < 0)
				continue;
			if (!consumer) {
				lttng_ust_lock_fd_tracker();
				ret = close(obj->wait_fd[i]);
				if (!ret) {
					lttng_ust_delete_fd_from_tracker(obj->wait_fd[i]);
				} else {
					PERROR("close");
					assert(0);
				}
				lttng_ust_unlock_fd_tracker();
			} else {
				ret = close(obj->wait_fd[i]);
				if (ret) {
					PERROR("close");
					assert(0);
				}
			}
		}
		free(obj->memory_map);
		break;
	}
	default:
		assert(0);
	}
}

void shm_object_table_destroy(struct shm_object_table *table, int consumer)
{
	int i;

	for (i = 0; i < table->allocated_len; i++)
		shmp_object_destroy(&table->objects[i], consumer);
	free(table);
}

/*
 * zalloc_shm - allocate memory within a shm object.
 *
 * Shared memory is already zeroed by shmget.
 * *NOT* multithread-safe (should be protected by mutex).
 * Returns a -1, -1 tuple on error.
 */
struct shm_ref zalloc_shm(struct shm_object *obj, size_t len)
{
	struct shm_ref ref;
	struct shm_ref shm_ref_error = { -1, -1 };

	if (obj->memory_map_size - obj->allocated_len < len)
		return shm_ref_error;
	ref.index = obj->index;
	ref.offset =  obj->allocated_len;
	obj->allocated_len += len;
	return ref;
}

void align_shm(struct shm_object *obj, size_t align)
{
	size_t offset_len = offset_align(obj->allocated_len, align);
	obj->allocated_len += offset_len;
}
