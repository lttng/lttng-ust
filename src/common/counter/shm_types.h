/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _LIBCOUNTER_SHM_TYPES_H
#define _LIBCOUNTER_SHM_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include "shm_internal.h"

enum lttng_counter_shm_object_type {
	LTTNG_COUNTER_SHM_OBJECT_SHM,
	LTTNG_COUNTER_SHM_OBJECT_MEM,
};

struct lttng_counter_shm_object {
	enum lttng_counter_shm_object_type type;
	size_t index;	/* within the object table */
	int shm_fd;	/* shm fd */
	char *memory_map;
	size_t memory_map_size;
	uint64_t allocated_len;
	int shm_fd_ownership;
};

struct lttng_counter_shm_object_table {
	size_t size;
	size_t allocated_len;
	struct lttng_counter_shm_object objects[];
};

struct lttng_counter_shm_handle {
	struct lttng_counter_shm_object_table *table;
};

#endif /* _LIBCOUNTER_SHM_TYPES_H */
