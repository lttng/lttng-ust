/*
 * counter/counter-internal.h
 *
 * LTTng Counters Internal Header
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

#ifndef _LTTNG_COUNTER_INTERNAL_H
#define _LTTNG_COUNTER_INTERNAL_H

#include <stdint.h>
#include <lttng/ust-config.h>
#include <urcu/compiler.h>
#include "counter-types.h"

static inline int lttng_counter_validate_indexes(const struct lib_counter_config *config,
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


static inline size_t lttng_counter_get_index(const struct lib_counter_config *config,
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
