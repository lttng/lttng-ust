#ifndef _LIBRINGBUFFER_SHM_TYPES_H
#define _LIBRINGBUFFER_SHM_TYPES_H

/*
 * libringbuffer/shm_types.h
 *
 * Copyright 2011 (c) - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Dual LGPL v2.1/GPL v2 license.
 */

#include <stdint.h>
#include "shm_internal.h"

struct channel;

struct shm_object {
	size_t index;	/* within the object table */
	int shm_fd;	/* shm fd */
	int wait_fd[2];	/* fd for wait/wakeup */
	char *memory_map;
	size_t memory_map_size;
	size_t allocated_len;
};

struct shm_object_table {
	size_t size;
	size_t allocated_len;
	struct shm_object objects[];
};

struct lttng_ust_shm_handle {
	struct shm_object_table *table;
	DECLARE_SHMP(struct channel, chan);
	/*
	 * In the consumer, chan points to a shadow copy, validated upon
	 * reception. The chan object is overridden in the consumer to
	 * point to this shadow copy.
	 */
	struct channel *shadow_chan;
};

#endif /* _LIBRINGBUFFER_SHM_TYPES_H */
