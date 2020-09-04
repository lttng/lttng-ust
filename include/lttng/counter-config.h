/*
 * lttng/counter-config.h
 *
 * LTTng Counters Configuration
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

#ifndef _LTTNG_COUNTER_CONFIG_H
#define _LTTNG_COUNTER_CONFIG_H

#include <stdint.h>

enum lib_counter_config_alloc {
	COUNTER_ALLOC_PER_CPU =	(1 << 0),
	COUNTER_ALLOC_GLOBAL  = (1 << 1),
};

enum lib_counter_config_sync {
	COUNTER_SYNC_PER_CPU,
	COUNTER_SYNC_GLOBAL,
};

struct lib_counter_config {
	uint32_t alloc;	/* enum lib_counter_config_alloc flags */
	enum lib_counter_config_sync sync;
	enum {
		COUNTER_ARITHMETIC_MODULAR,
		COUNTER_ARITHMETIC_SATURATE,	/* TODO */
	} arithmetic;
	enum {
		COUNTER_SIZE_8_BIT	= 1,
		COUNTER_SIZE_16_BIT	= 2,
		COUNTER_SIZE_32_BIT	= 4,
		COUNTER_SIZE_64_BIT	= 8,
	} counter_size;
};

#endif /* _LTTNG_COUNTER_CONFIG_H */
