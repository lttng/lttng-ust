/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng Counters Internal Header
 */

#ifndef _LTTNG_COUNTER_INTERNAL_H
#define _LTTNG_COUNTER_INTERNAL_H

#include <stdint.h>
#include <errno.h>

#include <lttng/ust-config.h>
#include <urcu/compiler.h>
#include "counter-types.h"

static inline int lttng_counter_validate_indexes(
		const struct lib_counter_config *config __attribute__((unused)),
		struct lib_counter *counter,
		const size_t *dimension_indexes)
{
	size_t nr_dimensions = counter->nr_dimensions, i;

	for (i = 0; i < nr_dimensions; i++) {
		if (caa_unlikely(dimension_indexes[i] >= counter->dimensions[i].max_nr_elem))
			return -EOVERFLOW;
	}
	return 0;
}


static inline size_t lttng_counter_get_index(
		const struct lib_counter_config *config __attribute__((unused)),
		struct lib_counter *counter,
		const size_t *dimension_indexes)
{
	size_t nr_dimensions = counter->nr_dimensions, i;
	size_t index = 0;

	for (i = 0; i < nr_dimensions; i++) {
		struct lib_counter_dimension *dimension = &counter->dimensions[i];
		const size_t *dimension_index = &dimension_indexes[i];

		index += *dimension_index * dimension->stride;
	}
	return index;
}

#endif /* _LTTNG_COUNTER_INTERNAL_H */
