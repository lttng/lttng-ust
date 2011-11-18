#ifndef _LIBRINGBUFFER_SMP_H
#define _LIBRINGBUFFER_SMP_H

/*
 * libringbuffer/smp.h
 *
 * Copyright 2011 (c) - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Dual LGPL v2.1/GPL v2 license.
 */

#include <lttng/core.h>
#include "getcpu.h"

/*
 * 4kB of per-cpu data available. Enough to hold the control structures,
 * but not ring buffers.
 */
#define PER_CPU_MEM_SIZE	4096

extern int __num_possible_cpus;
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
