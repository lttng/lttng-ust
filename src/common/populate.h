/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2024 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _UST_COMMON_POPULATE_H
#define _UST_COMMON_POPULATE_H

#include <stdbool.h>

bool lttng_ust_map_populate_cpu_is_enabled(int cpu)
	__attribute__((visibility("hidden")));

bool lttng_ust_map_populate_is_enabled(void)
	__attribute__((visibility("hidden")));

#endif /* _UST_COMMON_POPULATE_H */
