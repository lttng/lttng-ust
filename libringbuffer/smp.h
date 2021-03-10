/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _LIBRINGBUFFER_SMP_H
#define _LIBRINGBUFFER_SMP_H

#include "getcpu.h"

/*
 * 4kB of per-cpu data available. Enough to hold the control structures,
 * but not ring buffers.
 */
#define PER_CPU_MEM_SIZE	4096

__attribute__((visibility("hidden")))
extern int __num_possible_cpus;

__attribute__((visibility("hidden")))
extern void _get_num_possible_cpus(void);

static inline
int num_possible_cpus(void)
{
	if (!__num_possible_cpus)
		_get_num_possible_cpus();
	return __num_possible_cpus;
}

#define for_each_possible_cpu(cpu)		\
	for ((cpu) = 0; (cpu) < num_possible_cpus(); (cpu)++)

#endif /* _LIBRINGBUFFER_SMP_H */
