#ifndef _LIBCOUNTER_SMP_H
#define _LIBCOUNTER_SMP_H

/*
 * libcounter/smp.h
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

#include "helper.h"

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
