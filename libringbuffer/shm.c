/*
 * libringbuffer/shm.c
 *
 * Copyright 2011 (c) - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Dual LGPL v2.1/GPL v2 license.
 */

#include "shm.h"
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>	/* For mode constants */
#include <fcntl.h>	/* For O_* constants */
#include <assert.h>
#include <stdio.h>
#include <signal.h>
#include <dirent.h>
#include <ust/align.h>

struct shm_object_table *shm_object_table_create(size_t max_nb_obj)
{
	struct shm_object_table *table;

	table = zmalloc(sizeof(struct shm_object_table) +
			max_nb_obj * sizeof(table->objects[0]));
	table->size = max_nb_obj;
	return table;
}

struct shm_object *shm_object_table_append(struct shm_object_table *table,
					   size_t memory_map_size)
{
	int shmfd, waitfd[2], ret, i, sigblocked = 0;
	struct shm_object *obj;
	char *memory_map;
	char tmp_name[NAME_MAX] = "ust-shm-tmp-XXXXXX";
	sigset_t all_sigs, orig_sigs;

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

	/* shm_fd: create shm */

	/*
	 * Theoretically, we could leak a shm if the application crashes
	 * between open and unlink. Disable signals on this thread for
	 * increased safety against this scenario.
	 */
	sigfillset(&all_sigs);
	ret = pthread_sigmask(SIG_BLOCK, &all_sigs, &orig_sigs);
	if (ret == -1) {
		PERROR("pthread_sigmask");
		goto error_pthread_sigmask;
	}
	sigblocked = 1;

	/*
	 * Allocate shm, and immediately unlink its shm oject, keeping
	 * only the file descriptor as a reference to the object. If it
	 * already exists (caused by short race window during which the
	 * global object exists in a concurrent shm_open), simply retry.
	 * We specifically do _not_ use the / at the beginning of the
	 * pathname so that some OS implementations can keep it local to
	 * the process (POSIX leaves this implementation-defined).
	 */
	do {
		/*
		 * Using mktemp filename with O_CREAT | O_EXCL open
		 * flags.
		 */
		mktemp(tmp_name);
		if (tmp_name[0] == '\0') {
			PERROR("mktemp");
			goto error_shm_open;
		}
		shmfd = shm_open(tmp_name,
				 O_CREAT | O_EXCL | O_RDWR, 0700);
	} while (shmfd < 0 && (errno == EEXIST || errno == EACCES));
	if (shmfd < 0) {
		PERROR("shm_open");
		goto error_shm_open;
	}
	ret = shm_unlink(tmp_name);
	if (ret < 0 && errno != ENOENT) {
		PERROR("shm_unlink");
		goto error_shm_release;
	}
	sigblocked = 0;
	ret = pthread_sigmask(SIG_SETMASK, &orig_sigs, NULL);
	if (ret == -1) {
		PERROR("pthread_sigmask");
		goto error_sigmask_release;
	}
	ret = ftruncate(shmfd, memory_map_size);
	if (ret) {
		PERROR("ftruncate");
		goto error_ftruncate;
	}
	obj->shm_fd = shmfd;

	/* memory_map: mmap */
	memory_map = mmap(NULL, memory_map_size, PROT_READ | PROT_WRITE,
			  MAP_SHARED, shmfd, 0);
	if (memory_map == MAP_FAILED) {
		PERROR("mmap");
		goto error_mmap;
	}
	obj->memory_map = memory_map;
	obj->memory_map_size = memory_map_size;
	obj->allocated_len = 0;
	obj->index = table->allocated_len++;

	return obj;

error_mmap:
error_ftruncate:
error_shm_release:
error_sigmask_release:
	ret = close(shmfd);
	if (ret) {
		PERROR("close");
		assert(0);
	}
error_shm_open:
	if (sigblocked) {
		ret = pthread_sigmask(SIG_SETMASK, &orig_sigs, NULL);
		if (ret == -1) {
			PERROR("pthread_sigmask");
		}
	}
error_pthread_sigmask:
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

struct shm_object *shm_object_table_append_shadow(struct shm_object_table *table,
			int shm_fd, int wait_fd, size_t memory_map_size)
{
	struct shm_object *obj;
	char *memory_map;

	if (table->allocated_len >= table->size)
		return NULL;
	obj = &table->objects[table->allocated_len];

	/* wait_fd: set read end of the pipe. */
	obj->wait_fd[0] = wait_fd;
	obj->wait_fd[1] = -1;	/* write end is unset. */
	obj->shm_fd = shm_fd;

	/* memory_map: mmap */
	memory_map = mmap(NULL, memory_map_size, PROT_READ | PROT_WRITE,
			  MAP_SHARED, shm_fd, 0);
	if (memory_map == MAP_FAILED) {
		PERROR("mmap");
		goto error_mmap;
	}
	obj->memory_map = memory_map;
	obj->memory_map_size = memory_map_size;
	obj->allocated_len = memory_map_size;
	obj->index = table->allocated_len++;

	return obj;

error_mmap:
	return NULL;
}

static
void shmp_object_destroy(struct shm_object *obj)
{
	int ret, i;

        ret = munmap(obj->memory_map, obj->memory_map_size);
        if (ret) {
                PERROR("umnmap");
                assert(0);
        }
	ret = close(obj->shm_fd);
	if (ret) {
		PERROR("close");
		assert(0);
	}
	for (i = 0; i < 2; i++) {
		ret = close(obj->wait_fd[i]);
		if (ret) {
			PERROR("close");
			assert(0);
		}
	}
}

void shm_object_table_destroy(struct shm_object_table *table)
{
	int i;

	for (i = 0; i < table->allocated_len; i++)
		shmp_object_destroy(&table->objects[i]);
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
