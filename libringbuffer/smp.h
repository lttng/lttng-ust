#ifndef _LIBRINGBUFFER_SMP_H
#define _LIBRINGBUFFER_SMP_H

/*
 * libringbuffer/smp.h
 *
 * Copyright (C) 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; only
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

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
