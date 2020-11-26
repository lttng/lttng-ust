/* SPDX-License-Identifier: (GPL-2.0-only OR LGPL-2.1-only)
 *
 * counter.c
 *
 * Copyright (C) 2020 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#define _GNU_SOURCE
#include <errno.h>
#include "counter.h"
#include "counter-internal.h"
#include <lttng/bitmap.h>
#include <urcu/system.h>
#include <urcu/compiler.h>
#include <stdbool.h>
#include <helper.h>
#include <lttng/align.h>
#include "smp.h"
#include "shm.h"

static size_t lttng_counter_get_dimension_nr_elements(struct lib_counter_dimension *dimension)
{
	return dimension->max_nr_elem;
}

static int lttng_counter_init_stride(const struct lib_counter_config *config,
				      struct lib_counter *counter)
{
	size_t nr_dimensions = counter->nr_dimensions;
	size_t stride = 1;
	ssize_t i;

	for (i = nr_dimensions - 1; i >= 0; i--) {
		struct lib_counter_dimension *dimension = &counter->dimensions[i];
		size_t nr_elem;

		nr_elem = lttng_counter_get_dimension_nr_elements(dimension);
		dimension->stride = stride;
		/* nr_elem should be minimum 1 for each dimension. */
		if (!nr_elem)
			return -EINVAL;
		stride *= nr_elem;
		if (stride > SIZE_MAX / nr_elem)
			return -EINVAL;
	}
	return 0;
}

static int lttng_counter_layout_init(struct lib_counter *counter, int cpu, int shm_fd)
{
	struct lib_counter_layout *layout;
	size_t counter_size;
	size_t nr_elem = counter->allocated_elem;
	size_t shm_length = 0, counters_offset, overflow_offset, underflow_offset;
	struct lttng_counter_shm_object *shm_object;

	if (shm_fd < 0)
		return 0;	/* Skip, will be populated later. */

	if (cpu == -1)
		layout = &counter->global_counters;
	else
		layout = &counter->percpu_counters[cpu];
	switch (counter->config.counter_size) {
	case COUNTER_SIZE_8_BIT:
	case COUNTER_SIZE_16_BIT:
	case COUNTER_SIZE_32_BIT:
	case COUNTER_SIZE_64_BIT:
		counter_size = (size_t) counter->config.counter_size;
		break;
	default:
		return -EINVAL;
	}
	layout->shm_fd = shm_fd;
	counters_offset = shm_length;
	shm_length += counter_size * nr_elem;
	overflow_offset = shm_length;
	shm_length += LTTNG_UST_ALIGN(nr_elem, 8) / 8;
	underflow_offset = shm_length;
	shm_length += LTTNG_UST_ALIGN(nr_elem, 8) / 8;
	layout->shm_len = shm_length;
	if (counter->is_daemon) {
		/* Allocate and clear shared memory. */
		shm_object = lttng_counter_shm_object_table_alloc(counter->object_table,
			shm_length, LTTNG_COUNTER_SHM_OBJECT_SHM, shm_fd, cpu);
		if (!shm_object)
			return -ENOMEM;
	} else {
		/* Map pre-existing shared memory. */
		shm_object = lttng_counter_shm_object_table_append_shm(counter->object_table,
			shm_fd, shm_length);
		if (!shm_object)
			return -ENOMEM;
	}
	layout->counters = shm_object->memory_map + counters_offset;
	layout->overflow_bitmap = (unsigned long *)(shm_object->memory_map + overflow_offset);
	layout->underflow_bitmap = (unsigned long *)(shm_object->memory_map + underflow_offset);
	return 0;
}

int lttng_counter_set_global_shm(struct lib_counter *counter, int fd)
{
	struct lib_counter_config *config = &counter->config;
	struct lib_counter_layout *layout;

	if (!(config->alloc & COUNTER_ALLOC_GLOBAL))
		return -EINVAL;
	layout = &counter->global_counters;
	if (layout->shm_fd >= 0)
		return -EBUSY;
	return lttng_counter_layout_init(counter, -1, fd);
}

int lttng_counter_set_cpu_shm(struct lib_counter *counter, int cpu, int fd)
{
	struct lib_counter_config *config = &counter->config;
	struct lib_counter_layout *layout;

	if (cpu < 0 || cpu >= lttng_counter_num_possible_cpus())
		return -EINVAL;

	if (!(config->alloc & COUNTER_ALLOC_PER_CPU))
		return -EINVAL;
	layout = &counter->percpu_counters[cpu];
	if (layout->shm_fd >= 0)
		return -EBUSY;
	return lttng_counter_layout_init(counter, cpu, fd);
}

static
int lttng_counter_set_global_sum_step(struct lib_counter *counter,
				      int64_t global_sum_step)
{
	if (global_sum_step < 0)
		return -EINVAL;

	switch (counter->config.counter_size) {
	case COUNTER_SIZE_8_BIT:
		if (global_sum_step > INT8_MAX)
			return -EINVAL;
		counter->global_sum_step.s8 = (int8_t) global_sum_step;
		break;
	case COUNTER_SIZE_16_BIT:
		if (global_sum_step > INT16_MAX)
			return -EINVAL;
		counter->global_sum_step.s16 = (int16_t) global_sum_step;
		break;
	case COUNTER_SIZE_32_BIT:
		if (global_sum_step > INT32_MAX)
			return -EINVAL;
		counter->global_sum_step.s32 = (int32_t) global_sum_step;
		break;
	case COUNTER_SIZE_64_BIT:
		counter->global_sum_step.s64 = global_sum_step;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static
int validate_args(const struct lib_counter_config *config,
	size_t nr_dimensions,
	const size_t *max_nr_elem,
	int64_t global_sum_step,
	int global_counter_fd,
	int nr_counter_cpu_fds,
	const int *counter_cpu_fds)
{
	int nr_cpus = lttng_counter_num_possible_cpus();

	if (CAA_BITS_PER_LONG != 64 && config->counter_size == COUNTER_SIZE_64_BIT) {
		WARN_ON_ONCE(1);
		return -1;
	}
	if (!max_nr_elem)
		return -1;
	/*
	 * global sum step is only useful with allocating both per-cpu
	 * and global counters.
	 */
	if (global_sum_step && (!(config->alloc & COUNTER_ALLOC_GLOBAL) ||
			!(config->alloc & COUNTER_ALLOC_PER_CPU)))
		return -1;
	if (!(config->alloc & COUNTER_ALLOC_GLOBAL) && global_counter_fd >= 0)
		return -1;
	if (!(config->alloc & COUNTER_ALLOC_PER_CPU) && counter_cpu_fds)
		return -1;
	if (!(config->alloc & COUNTER_ALLOC_PER_CPU) && counter_cpu_fds >= 0)
		return -1;
	if (counter_cpu_fds && nr_cpus != nr_counter_cpu_fds)
		return -1;
	return 0;
}

struct lib_counter *lttng_counter_create(const struct lib_counter_config *config,
					 size_t nr_dimensions,
					 const size_t *max_nr_elem,
					 int64_t global_sum_step,
					 int global_counter_fd,
					 int nr_counter_cpu_fds,
					 const int *counter_cpu_fds,
					 bool is_daemon)
{
	struct lib_counter *counter;
	size_t dimension, nr_elem = 1;
	int cpu, ret;
	int nr_handles = 0;
	int nr_cpus = lttng_counter_num_possible_cpus();

	if (validate_args(config, nr_dimensions, max_nr_elem,
			global_sum_step, global_counter_fd, nr_counter_cpu_fds,
			counter_cpu_fds))
		return NULL;
	counter = zmalloc(sizeof(struct lib_counter));
	if (!counter)
		return NULL;
	counter->global_counters.shm_fd = -1;
	counter->config = *config;
	counter->is_daemon = is_daemon;
	if (lttng_counter_set_global_sum_step(counter, global_sum_step))
		goto error_sum_step;
	counter->nr_dimensions = nr_dimensions;
	counter->dimensions = zmalloc(nr_dimensions * sizeof(*counter->dimensions));
	if (!counter->dimensions)
		goto error_dimensions;
	for (dimension = 0; dimension < nr_dimensions; dimension++)
		counter->dimensions[dimension].max_nr_elem = max_nr_elem[dimension];
	if (config->alloc & COUNTER_ALLOC_PER_CPU) {
		counter->percpu_counters = zmalloc(sizeof(struct lib_counter_layout) * nr_cpus);
		if (!counter->percpu_counters)
			goto error_alloc_percpu;
		lttng_counter_for_each_possible_cpu(cpu)
			counter->percpu_counters[cpu].shm_fd = -1;
	}

	if (lttng_counter_init_stride(config, counter))
		goto error_init_stride;
	//TODO saturation values.
	for (dimension = 0; dimension < counter->nr_dimensions; dimension++)
		nr_elem *= lttng_counter_get_dimension_nr_elements(&counter->dimensions[dimension]);
	counter->allocated_elem = nr_elem;

	if (config->alloc & COUNTER_ALLOC_GLOBAL)
		nr_handles++;
	if (config->alloc & COUNTER_ALLOC_PER_CPU)
		nr_handles += nr_cpus;
	/* Allocate table for global and per-cpu counters. */
	counter->object_table = lttng_counter_shm_object_table_create(nr_handles);
	if (!counter->object_table)
		goto error_alloc_object_table;

	if (config->alloc & COUNTER_ALLOC_GLOBAL) {
		ret = lttng_counter_layout_init(counter, -1, global_counter_fd);	/* global */
		if (ret)
			goto layout_init_error;
	}
	if ((config->alloc & COUNTER_ALLOC_PER_CPU) && counter_cpu_fds) {
		lttng_counter_for_each_possible_cpu(cpu) {
			ret = lttng_counter_layout_init(counter, cpu, counter_cpu_fds[cpu]);
			if (ret)
				goto layout_init_error;
		}
	}
	return counter;

layout_init_error:
	lttng_counter_shm_object_table_destroy(counter->object_table, is_daemon);
error_alloc_object_table:
error_init_stride:
	free(counter->percpu_counters);
error_alloc_percpu:
	free(counter->dimensions);
error_dimensions:
error_sum_step:
	free(counter);
	return NULL;
}

void lttng_counter_destroy(struct lib_counter *counter)
{
	struct lib_counter_config *config = &counter->config;

	if (config->alloc & COUNTER_ALLOC_PER_CPU)
		free(counter->percpu_counters);
	lttng_counter_shm_object_table_destroy(counter->object_table, counter->is_daemon);
	free(counter->dimensions);
	free(counter);
}

int lttng_counter_get_global_shm(struct lib_counter *counter, int *fd, size_t *len)
{
	int shm_fd;

	shm_fd = counter->global_counters.shm_fd;
	if (shm_fd < 0)
		return -1;
	*fd = shm_fd;
	*len = counter->global_counters.shm_len;
	return 0;
}

int lttng_counter_get_cpu_shm(struct lib_counter *counter, int cpu, int *fd, size_t *len)
{
	struct lib_counter_layout *layout;
	int shm_fd;

	if (cpu >= lttng_counter_num_possible_cpus())
		return -1;
	layout = &counter->percpu_counters[cpu];
	shm_fd = layout->shm_fd;
	if (shm_fd < 0)
		return -1;
	*fd = shm_fd;
	*len = layout->shm_len;
	return 0;
}

int lttng_counter_read(const struct lib_counter_config *config,
		       struct lib_counter *counter,
		       const size_t *dimension_indexes,
		       int cpu, int64_t *value, bool *overflow,
		       bool *underflow)
{
	size_t index;
	struct lib_counter_layout *layout;

	if (caa_unlikely(lttng_counter_validate_indexes(config, counter, dimension_indexes)))
		return -EOVERFLOW;
	index = lttng_counter_get_index(config, counter, dimension_indexes);

	switch (config->alloc) {
	case COUNTER_ALLOC_PER_CPU:
		if (cpu < 0 || cpu >= lttng_counter_num_possible_cpus())
			return -EINVAL;
		layout = &counter->percpu_counters[cpu];
		break;
	case COUNTER_ALLOC_PER_CPU | COUNTER_ALLOC_GLOBAL:
		if (cpu >= 0) {
			if (cpu >= lttng_counter_num_possible_cpus())
				return -EINVAL;
			layout = &counter->percpu_counters[cpu];
		} else {
			layout = &counter->global_counters;
		}
		break;
	case COUNTER_ALLOC_GLOBAL:
		if (cpu >= 0)
			return -EINVAL;
		layout = &counter->global_counters;
		break;
	default:
		return -EINVAL;
	}
	if (caa_unlikely(!layout->counters))
		return -ENODEV;

	switch (config->counter_size) {
	case COUNTER_SIZE_8_BIT:
	{
		int8_t *int_p = (int8_t *) layout->counters + index;
		*value = (int64_t) CMM_LOAD_SHARED(*int_p);
		break;
	}
	case COUNTER_SIZE_16_BIT:
	{
		int16_t *int_p = (int16_t *) layout->counters + index;
		*value = (int64_t) CMM_LOAD_SHARED(*int_p);
		break;
	}
	case COUNTER_SIZE_32_BIT:
	{
		int32_t *int_p = (int32_t *) layout->counters + index;
		*value = (int64_t) CMM_LOAD_SHARED(*int_p);
		break;
	}
#if CAA_BITS_PER_LONG == 64
	case COUNTER_SIZE_64_BIT:
	{
		int64_t *int_p = (int64_t *) layout->counters + index;
		*value = CMM_LOAD_SHARED(*int_p);
		break;
	}
#endif
	default:
		return -EINVAL;
	}
	*overflow = lttng_bitmap_test_bit(index, layout->overflow_bitmap);
	*underflow = lttng_bitmap_test_bit(index, layout->underflow_bitmap);
	return 0;
}

int lttng_counter_aggregate(const struct lib_counter_config *config,
			    struct lib_counter *counter,
			    const size_t *dimension_indexes,
			    int64_t *value, bool *overflow,
			    bool *underflow)
{
	int cpu, ret;
	int64_t v, sum = 0;
	bool of, uf;

	*overflow = false;
	*underflow = false;

	switch (config->alloc) {
	case COUNTER_ALLOC_GLOBAL:	/* Fallthrough */
	case COUNTER_ALLOC_PER_CPU | COUNTER_ALLOC_GLOBAL:
		/* Read global counter. */
		ret = lttng_counter_read(config, counter, dimension_indexes,
					 -1, &v, &of, &uf);
		if (ret < 0)
			return ret;
		sum += v;
		*overflow |= of;
		*underflow |= uf;
		break;
	case COUNTER_ALLOC_PER_CPU:
		break;
	default:
		return -EINVAL;
	}

	switch (config->alloc) {
	case COUNTER_ALLOC_GLOBAL:
		break;
	case COUNTER_ALLOC_PER_CPU | COUNTER_ALLOC_GLOBAL:	/* Fallthrough */
	case COUNTER_ALLOC_PER_CPU:
		lttng_counter_for_each_possible_cpu(cpu) {
			int64_t old = sum;

			ret = lttng_counter_read(config, counter, dimension_indexes,
						 cpu, &v, &of, &uf);
			if (ret < 0)
				return ret;
			*overflow |= of;
			*underflow |= uf;
			/* Overflow is defined on unsigned types. */
			sum = (int64_t) ((uint64_t) old + (uint64_t) v);
			if (v > 0 && sum < old)
				*overflow = true;
			else if (v < 0 && sum > old)
				*underflow = true;
		}
		break;
	default:
		return -EINVAL;
	}
	*value = sum;
	return 0;
}

static
int lttng_counter_clear_cpu(const struct lib_counter_config *config,
			    struct lib_counter *counter,
			    const size_t *dimension_indexes,
			    int cpu)
{
	size_t index;
	struct lib_counter_layout *layout;

	if (caa_unlikely(lttng_counter_validate_indexes(config, counter, dimension_indexes)))
		return -EOVERFLOW;
	index = lttng_counter_get_index(config, counter, dimension_indexes);

	switch (config->alloc) {
	case COUNTER_ALLOC_PER_CPU:
		if (cpu < 0 || cpu >= lttng_counter_num_possible_cpus())
			return -EINVAL;
		layout = &counter->percpu_counters[cpu];
		break;
	case COUNTER_ALLOC_PER_CPU | COUNTER_ALLOC_GLOBAL:
		if (cpu >= 0) {
			if (cpu >= lttng_counter_num_possible_cpus())
				return -EINVAL;
			layout = &counter->percpu_counters[cpu];
		} else {
			layout = &counter->global_counters;
		}
		break;
	case COUNTER_ALLOC_GLOBAL:
		if (cpu >= 0)
			return -EINVAL;
		layout = &counter->global_counters;
		break;
	default:
		return -EINVAL;
	}
	if (caa_unlikely(!layout->counters))
		return -ENODEV;

	switch (config->counter_size) {
	case COUNTER_SIZE_8_BIT:
	{
		int8_t *int_p = (int8_t *) layout->counters + index;
		CMM_STORE_SHARED(*int_p, 0);
		break;
	}
	case COUNTER_SIZE_16_BIT:
	{
		int16_t *int_p = (int16_t *) layout->counters + index;
		CMM_STORE_SHARED(*int_p, 0);
		break;
	}
	case COUNTER_SIZE_32_BIT:
	{
		int32_t *int_p = (int32_t *) layout->counters + index;
		CMM_STORE_SHARED(*int_p, 0);
		break;
	}
#if CAA_BITS_PER_LONG == 64
	case COUNTER_SIZE_64_BIT:
	{
		int64_t *int_p = (int64_t *) layout->counters + index;
		CMM_STORE_SHARED(*int_p, 0);
		break;
	}
#endif
	default:
		return -EINVAL;
	}
	lttng_bitmap_clear_bit(index, layout->overflow_bitmap);
	lttng_bitmap_clear_bit(index, layout->underflow_bitmap);
	return 0;
}

int lttng_counter_clear(const struct lib_counter_config *config,
			struct lib_counter *counter,
			const size_t *dimension_indexes)
{
	int cpu, ret;

	switch (config->alloc) {
	case COUNTER_ALLOC_PER_CPU:
		break;
	case COUNTER_ALLOC_GLOBAL:	/* Fallthrough */
	case COUNTER_ALLOC_PER_CPU | COUNTER_ALLOC_GLOBAL:
		/* Clear global counter. */
		ret = lttng_counter_clear_cpu(config, counter, dimension_indexes, -1);
		if (ret < 0)
			return ret;
		break;
	default:
		return -EINVAL;
	}

	switch (config->alloc) {
	case COUNTER_ALLOC_PER_CPU:	/* Fallthrough */
	case COUNTER_ALLOC_PER_CPU | COUNTER_ALLOC_GLOBAL:
		lttng_counter_for_each_possible_cpu(cpu) {
			ret = lttng_counter_clear_cpu(config, counter, dimension_indexes, cpu);
			if (ret < 0)
				return ret;
		}
		break;
	case COUNTER_ALLOC_GLOBAL:
		break;
	default:
		return -EINVAL;
	}
	return 0;
}
