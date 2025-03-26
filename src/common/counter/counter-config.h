/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng Counters Configuration
 */

#ifndef _LTTNG_COUNTER_CONFIG_H
#define _LTTNG_COUNTER_CONFIG_H

#include <stdint.h>

enum lib_counter_config_alloc {
	COUNTER_ALLOC_PER_CPU =	(1 << 0),
	COUNTER_ALLOC_PER_CHANNEL  = (1 << 1),
};

enum lib_counter_config_sync {
	COUNTER_SYNC_PER_CPU,
	COUNTER_SYNC_PER_CHANNEL,
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
