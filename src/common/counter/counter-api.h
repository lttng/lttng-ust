/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng Counters API, requiring counter/config.h
 */

#ifndef _LTTNG_COUNTER_API_H
#define _LTTNG_COUNTER_API_H

#include <stdint.h>
#include <limits.h>
#include <errno.h>
#include "counter.h"
#include "counter-internal.h"
#include <urcu/compiler.h>
#include <urcu/uatomic.h>
#include "common/bitmap.h"
#include "common/getcpu.h"

/*
 * Using unsigned arithmetic because overflow is defined.
 */
static inline int __lttng_counter_add(const struct lib_counter_config *config,
				      enum lib_counter_config_alloc alloc,
				      enum lib_counter_config_sync sync,
				      struct lib_counter *counter,
				      const size_t *dimension_indexes, int64_t v,
				      int64_t *remainder)
{
	size_t index;
	bool overflow = false, underflow = false;
	struct lib_counter_layout *layout;
	int64_t move_sum = 0;

	if (caa_unlikely(lttng_counter_validate_indexes(config, counter, dimension_indexes)))
		return -EOVERFLOW;
	index = lttng_counter_get_index(config, counter, dimension_indexes);

	switch (alloc) {
	case COUNTER_ALLOC_PER_CPU:
		layout = &counter->percpu_counters[lttng_ust_get_cpu()];
		break;
	case COUNTER_ALLOC_GLOBAL:
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
		int8_t old, n, res;
		int8_t global_sum_step = counter->global_sum_step.s8;

		res = *int_p;
		switch (sync) {
		case COUNTER_SYNC_PER_CPU:
		{
			do {
				move_sum = 0;
				old = res;
				n = (int8_t) ((uint8_t) old + (uint8_t) v);
				if (caa_unlikely(n > (int8_t) global_sum_step))
					move_sum = (int8_t) global_sum_step / 2;
				else if (caa_unlikely(n < -(int8_t) global_sum_step))
					move_sum = -((int8_t) global_sum_step / 2);
				n -= move_sum;
				res = uatomic_cmpxchg(int_p, old, n);
			} while (old != res);
			break;
		}
		case COUNTER_SYNC_GLOBAL:
		{
			do {
				old = res;
				n = (int8_t) ((uint8_t) old + (uint8_t) v);
				res = uatomic_cmpxchg(int_p, old, n);
			} while (old != res);
			break;
		}
		default:
			return -EINVAL;
		}
		if (v > 0 && (v >= UINT8_MAX || n < old))
			overflow = true;
		else if (v < 0 && (v <= -(int64_t) UINT8_MAX || n > old))
			underflow = true;
		break;
	}
	case COUNTER_SIZE_16_BIT:
	{
		int16_t *int_p = (int16_t *) layout->counters + index;
		int16_t old, n, res;
		int16_t global_sum_step = counter->global_sum_step.s16;

		res = *int_p;
		switch (sync) {
		case COUNTER_SYNC_PER_CPU:
		{
			do {
				move_sum = 0;
				old = res;
				n = (int16_t) ((uint16_t) old + (uint16_t) v);
				if (caa_unlikely(n > (int16_t) global_sum_step))
					move_sum = (int16_t) global_sum_step / 2;
				else if (caa_unlikely(n < -(int16_t) global_sum_step))
					move_sum = -((int16_t) global_sum_step / 2);
				n -= move_sum;
				res = uatomic_cmpxchg(int_p, old, n);
			} while (old != res);
			break;
		}
		case COUNTER_SYNC_GLOBAL:
		{
			do {
				old = res;
				n = (int16_t) ((uint16_t) old + (uint16_t) v);
				res = uatomic_cmpxchg(int_p, old, n);
			} while (old != res);
			break;
		}
		default:
			return -EINVAL;
		}
		if (v > 0 && (v >= UINT16_MAX || n < old))
			overflow = true;
		else if (v < 0 && (v <= -(int64_t) UINT16_MAX || n > old))
			underflow = true;
		break;
	}
	case COUNTER_SIZE_32_BIT:
	{
		int32_t *int_p = (int32_t *) layout->counters + index;
		int32_t old, n, res;
		int32_t global_sum_step = counter->global_sum_step.s32;

		res = *int_p;
		switch (sync) {
		case COUNTER_SYNC_PER_CPU:
		{
			do {
				move_sum = 0;
				old = res;
				n = (int32_t) ((uint32_t) old + (uint32_t) v);
				if (caa_unlikely(n > (int32_t) global_sum_step))
					move_sum = (int32_t) global_sum_step / 2;
				else if (caa_unlikely(n < -(int32_t) global_sum_step))
					move_sum = -((int32_t) global_sum_step / 2);
				n -= move_sum;
				res = uatomic_cmpxchg(int_p, old, n);
			} while (old != res);
			break;
		}
		case COUNTER_SYNC_GLOBAL:
		{
			do {
				old = res;
				n = (int32_t) ((uint32_t) old + (uint32_t) v);
				res = uatomic_cmpxchg(int_p, old, n);
			} while (old != res);
			break;
		}
		default:
			return -EINVAL;
		}
		if (v > 0 && (v >= UINT32_MAX || n < old))
			overflow = true;
		else if (v < 0 && (v <= -(int64_t) UINT32_MAX || n > old))
			underflow = true;
		break;
	}
#if CAA_BITS_PER_LONG == 64
	case COUNTER_SIZE_64_BIT:
	{
		int64_t *int_p = (int64_t *) layout->counters + index;
		int64_t old, n, res;
		int64_t global_sum_step = counter->global_sum_step.s64;

		res = *int_p;
		switch (sync) {
		case COUNTER_SYNC_PER_CPU:
		{
			do {
				move_sum = 0;
				old = res;
				n = (int64_t) ((uint64_t) old + (uint64_t) v);
				if (caa_unlikely(n > (int64_t) global_sum_step))
					move_sum = (int64_t) global_sum_step / 2;
				else if (caa_unlikely(n < -(int64_t) global_sum_step))
					move_sum = -((int64_t) global_sum_step / 2);
				n -= move_sum;
				res = uatomic_cmpxchg(int_p, old, n);
			} while (old != res);
			break;
		}
		case COUNTER_SYNC_GLOBAL:
		{
			do {
				old = res;
				n = (int64_t) ((uint64_t) old + (uint64_t) v);
				res = uatomic_cmpxchg(int_p, old, n);
			} while (old != res);
			break;
		}
		default:
			return -EINVAL;
		}
		if (v > 0 && n < old)
			overflow = true;
		else if (v < 0 && n > old)
			underflow = true;
		break;
	}
#endif
	default:
		return -EINVAL;
	}
	if (caa_unlikely(overflow && !lttng_bitmap_test_bit(index, layout->overflow_bitmap)))
		lttng_bitmap_set_bit(index, layout->overflow_bitmap);
	else if (caa_unlikely(underflow && !lttng_bitmap_test_bit(index, layout->underflow_bitmap)))
		lttng_bitmap_set_bit(index, layout->underflow_bitmap);
	if (remainder)
		*remainder = move_sum;
	return 0;
}

static inline int __lttng_counter_add_percpu(const struct lib_counter_config *config,
					     struct lib_counter *counter,
					     const size_t *dimension_indexes, int64_t v)
{
	int64_t move_sum = 0;
	int ret;

	ret = __lttng_counter_add(config, COUNTER_ALLOC_PER_CPU, config->sync,
				       counter, dimension_indexes, v, &move_sum);
	if (caa_unlikely(ret))
		return ret;
	if (caa_unlikely(move_sum))
		return __lttng_counter_add(config, COUNTER_ALLOC_GLOBAL, COUNTER_SYNC_GLOBAL,
					   counter, dimension_indexes, move_sum, NULL);
	return 0;
}

static inline int __lttng_counter_add_global(const struct lib_counter_config *config,
					     struct lib_counter *counter,
					     const size_t *dimension_indexes, int64_t v)
{
	return __lttng_counter_add(config, COUNTER_ALLOC_GLOBAL, config->sync, counter,
				   dimension_indexes, v, NULL);
}

static inline int lttng_counter_add(const struct lib_counter_config *config,
				    struct lib_counter *counter,
				    const size_t *dimension_indexes, int64_t v)
{
	switch (config->alloc) {
	case COUNTER_ALLOC_PER_CPU:	/* Fallthrough */
	case COUNTER_ALLOC_PER_CPU | COUNTER_ALLOC_GLOBAL:
		return __lttng_counter_add_percpu(config, counter, dimension_indexes, v);
	case COUNTER_ALLOC_GLOBAL:
		return __lttng_counter_add_global(config, counter, dimension_indexes, v);
	default:
		return -EINVAL;
	}
}

static inline int lttng_counter_inc(const struct lib_counter_config *config,
				    struct lib_counter *counter,
				    const size_t *dimension_indexes)
{
	return lttng_counter_add(config, counter, dimension_indexes, 1);
}

static inline int lttng_counter_dec(const struct lib_counter_config *config,
				    struct lib_counter *counter,
				    const size_t *dimension_indexes)
{
	return lttng_counter_add(config, counter, dimension_indexes, -1);
}

#endif /* _LTTNG_COUNTER_API_H */
