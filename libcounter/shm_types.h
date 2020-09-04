#ifndef _LIBCOUNTER_SHM_TYPES_H
#define _LIBCOUNTER_SHM_TYPES_H

/*
 * libcounter/shm_types.h
 *
 * Copyright (C) 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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
