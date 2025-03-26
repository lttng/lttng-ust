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

/* max_nr_elem is for each dimension. */
struct lib_counter *lttng_counter_create(const struct lib_counter_config *config,
					 size_t nr_dimensions,
					 const size_t *max_nr_elem,
					 int64_t global_sum_step,
					 int channel_counter_fd,
					 int nr_counter_cpu_fds,
					 const int *counter_cpu_fds,
					 bool is_daemon)
	__attribute__((visibility("hidden")));

void lttng_counter_destroy(struct lib_counter *counter)
	__attribute__((visibility("hidden")));

int lttng_counter_set_channel_shm(struct lib_counter *counter, int fd)
	__attribute__((visibility("hidden")));

int lttng_counter_set_cpu_shm(struct lib_counter *counter, int cpu, int fd)
	__attribute__((visibility("hidden")));

int lttng_counter_get_channel_shm(struct lib_counter *counter, int *fd, size_t *len)
	__attribute__((visibility("hidden")));

int lttng_counter_get_cpu_shm(struct lib_counter *counter, int cpu, int *fd, size_t *len)
	__attribute__((visibility("hidden")));

/*
 * Has counter received all expected shm ?
 */
bool lttng_counter_ready(struct lib_counter *counter)
	__attribute__((visibility("hidden")));

int lttng_counter_read(const struct lib_counter_config *config,
		       struct lib_counter *counter,
		       const size_t *dimension_indexes,
		       int cpu, int64_t *value,
		       bool *overflow, bool *underflow)
	__attribute__((visibility("hidden")));

int lttng_counter_aggregate(const struct lib_counter_config *config,
			    struct lib_counter *counter,
			    const size_t *dimension_indexes,
			    int64_t *value,
			    bool *overflow, bool *underflow)
	__attribute__((visibility("hidden")));

int lttng_counter_clear(const struct lib_counter_config *config,
			struct lib_counter *counter,
			const size_t *dimension_indexes)
	__attribute__((visibility("hidden")));

#endif /* _LTTNG_COUNTER_H */
