/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng Counters API
 */

#ifndef _LTTNG_COUNTER_H
#define _LTTNG_COUNTER_H

#include <stdint.h>
#include <lttng/ust-config.h>
#include "counter-types.h"
#include "helper.h"

/* max_nr_elem is for each dimension. */
LTTNG_HIDDEN
struct lib_counter *lttng_counter_create(const struct lib_counter_config *config,
					 size_t nr_dimensions,
					 const size_t *max_nr_elem,
					 int64_t global_sum_step,
					 int global_counter_fd,
					 int nr_counter_cpu_fds,
					 const int *counter_cpu_fds,
					 bool is_daemon);
LTTNG_HIDDEN
void lttng_counter_destroy(struct lib_counter *counter);

LTTNG_HIDDEN
int lttng_counter_set_global_shm(struct lib_counter *counter, int fd);
LTTNG_HIDDEN
int lttng_counter_set_cpu_shm(struct lib_counter *counter, int cpu, int fd);

LTTNG_HIDDEN
int lttng_counter_get_global_shm(struct lib_counter *counter, int *fd, size_t *len);
LTTNG_HIDDEN
int lttng_counter_get_cpu_shm(struct lib_counter *counter, int cpu, int *fd, size_t *len);

LTTNG_HIDDEN
int lttng_counter_read(const struct lib_counter_config *config,
		       struct lib_counter *counter,
		       const size_t *dimension_indexes,
		       int cpu, int64_t *value,
		       bool *overflow, bool *underflow);
LTTNG_HIDDEN
int lttng_counter_aggregate(const struct lib_counter_config *config,
			    struct lib_counter *counter,
			    const size_t *dimension_indexes,
			    int64_t *value,
			    bool *overflow, bool *underflow);
LTTNG_HIDDEN
int lttng_counter_clear(const struct lib_counter_config *config,
			struct lib_counter *counter,
			const size_t *dimension_indexes);

#endif /* _LTTNG_COUNTER_H */
