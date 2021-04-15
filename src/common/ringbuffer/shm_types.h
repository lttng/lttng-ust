/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _LIBRINGBUFFER_SHM_TYPES_H
#define _LIBRINGBUFFER_SHM_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include "shm_internal.h"

struct lttng_ust_ring_buffer_channel;

enum shm_object_type {
	SHM_OBJECT_SHM,
	SHM_OBJECT_MEM,
};

struct shm_object {
	enum shm_object_type type;
	size_t index;	/* within the object table */
	int shm_fd;	/* shm fd */
	int wait_fd[2];	/* fd for wait/wakeup */
	char *memory_map;
	size_t memory_map_size;
	uint64_t allocated_len;
	int shm_fd_ownership;
};

struct shm_object_table {
	size_t size;
	size_t allocated_len;
	struct shm_object objects[];
};

struct lttng_ust_shm_handle {
	struct shm_object_table *table;
	DECLARE_SHMP(struct lttng_ust_ring_buffer_channel, chan);
};

#endif /* _LIBRINGBUFFER_SHM_TYPES_H */
