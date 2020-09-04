/*
 * lttng/counter.h
 *
 * LTTng Counters API
 *
 * Copyright (C) 2020 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
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
					 int global_counter_fd,
					 int nr_counter_cpu_fds,
					 const int *counter_cpu_fds,
					 bool is_daemon);
void lttng_counter_destroy(struct lib_counter *counter);

int lttng_counter_set_global_shm(struct lib_counter *counter, int fd);
int lttng_counter_set_cpu_shm(struct lib_counter *counter, int cpu, int fd);

int lttng_counter_get_global_shm(struct lib_counter *counter, int *fd, size_t *len);
int lttng_counter_get_cpu_shm(struct lib_counter *counter, int cpu, int *fd, size_t *len);

int lttng_counter_read(const struct lib_counter_config *config,
		       struct lib_counter *counter,
		       const size_t *dimension_indexes,
		       int cpu, int64_t *value,
		       bool *overflow, bool *underflow);
int lttng_counter_aggregate(const struct lib_counter_config *config,
			    struct lib_counter *counter,
			    const size_t *dimension_indexes,
			    int64_t *value,
			    bool *overflow, bool *underflow);
int lttng_counter_clear(const struct lib_counter_config *config,
			struct lib_counter *counter,
			const size_t *dimension_indexes);

#endif /* _LTTNG_COUNTER_H */
