/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _LIBCOUNTER_SMP_H
#define _LIBCOUNTER_SMP_H

#include "ust-helper.h"

/*
 * 4kB of per-cpu data available.
 */
#define LTTNG_COUNTER_PER_CPU_MEM_SIZE	4096

LTTNG_HIDDEN
extern int __lttng_counter_num_possible_cpus;
LTTNG_HIDDEN
extern void _lttng_counter_get_num_possible_cpus(void);

static inline
int lttng_counter_num_possible_cpus(void)
{
	if (!__lttng_counter_num_possible_cpus)
		_lttng_counter_get_num_possible_cpus();
	return __lttng_counter_num_possible_cpus;
}

#define lttng_counter_for_each_possible_cpu(cpu)		\
	for ((cpu) = 0; (cpu) < lttng_counter_num_possible_cpus(); (cpu)++)

#endif /* _LIBCOUNTER_SMP_H */
