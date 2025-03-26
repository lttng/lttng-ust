/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng Counters Types
 */

#ifndef _LTTNG_COUNTER_TYPES_H
#define _LTTNG_COUNTER_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>
#include "counter-config.h"
#include <lttng/ust-config.h>
#include "shm_types.h"

struct lib_counter_dimension {
	/*
	 * Max. number of indexable elements.
	 */
	size_t max_nr_elem;
	/*
	 * The stride for a dimension is the multiplication factor which
	 * should be applied to its index to take into account other
	 * dimensions nested inside.
	 */
	size_t stride;
};

struct lib_counter_layout {
	void *counters;
	unsigned long *overflow_bitmap;
	unsigned long *underflow_bitmap;
	int shm_fd;
	size_t shm_len;
	struct lttng_counter_shm_handle handle;
};

enum lib_counter_arithmetic {
	LIB_COUNTER_ARITHMETIC_MODULAR,
	LIB_COUNTER_ARITHMETIC_SATURATE,
};

struct lib_counter {
	size_t nr_dimensions;
	int64_t allocated_elem;
	struct lib_counter_dimension *dimensions;
	enum lib_counter_arithmetic arithmetic;
	union {
		struct {
			int32_t max, min;
		} limits_32_bit;
		struct {
			int64_t max, min;
		} limits_64_bit;
	} saturation;
	union {
		int8_t s8;
		int16_t s16;
		int32_t s32;
		int64_t s64;
	} global_sum_step;		/* 0 if unused */
	struct lib_counter_config config;

	struct lib_counter_layout channel_counters;
	struct lib_counter_layout *percpu_counters;

	size_t expected_shm;
	size_t received_shm;

	bool is_daemon;
	struct lttng_counter_shm_object_table *object_table;
};

#endif /* _LTTNG_COUNTER_TYPES_H */
