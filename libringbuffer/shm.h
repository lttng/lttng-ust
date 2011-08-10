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
#include <ust/usterr-signal-safe.h>
#include "ust/core.h"

#define SHM_MAGIC	0x54335433
#define SHM_MAJOR	0
#define SHM_MINOR	1

/*
 * Defining a max shm offset, for debugging purposes.
 */
#if (CAA_BITS_PER_LONG == 32)
/* Define the maximum shared memory size to 128MB on 32-bit machines */
#define MAX_SHM_SIZE	134217728
#else
/* Define the maximum shared memory size to 8GB on 64-bit machines */
#define MAX_SHM_SIZE	8589934592
#endif

#define DECLARE_SHMP(type, name)	type *****name

struct shm_header {
	uint32_t magic;
	uint8_t major;
	uint8_t minor;
	uint8_t bits_per_long;
	size_t shm_size, shm_allocated;

	DECLARE_SHMP(struct channel, chan);
};

struct shm_handle {
	struct shm_header *header;	/* beginning of mapping */
	int shmfd;			/* process-local file descriptor */
};

#define shmp(shm_offset)		\
	((__typeof__(****(shm_offset))) (((char *) &(shm_offset)) + (ptrdiff_t) (shm_offset)))

#define _shmp_abs(a)	((a < 0) ? -(a) : (a))

static inline
void _set_shmp(ptrdiff_t *shm_offset, void *ptr)
{
	*shm_offset = (((char *) ptr) - ((char *) shm_offset));
	assert(_shmp_abs(*shm_offset) < MAX_SHM_SIZE);
}

#define set_shmp(shm_offset, ptr)	\
	_set_shmp((ptrdiff_t *) ****(shm_offset), ptr)

/* Shared memory is already zeroed by shmget */
/* *NOT* multithread-safe (should be protected by mutex) */
static inline
void *zalloc_shm(struct shm_header *shm_header, size_t len)
{
	void *ret;

	if (shm_header->shm_size - shm_header->shm_allocated < len)
		return NULL;
	ret = (char *) shm_header + shm_header->shm_allocated;
	shm_header->shm_allocated += len;
	return ret;
}

static inline
void align_shm(struct shm_header *shm_header, size_t align)
{
	size_t offset_len = offset_align(shm_header->shm_allocated, align);
	shm_header->shm_allocated += offset_len;
}

#endif /* _LIBRINGBUFFER_SHM_H */
