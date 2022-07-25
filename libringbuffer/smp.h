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

/*
 * Get the CPU possible mask string from sysfs.
 *
 * buf: the buffer where the mask will be read.
 * max_bytes: the maximum number of bytes to write in the buffer.
 *
 * Returns the number of bytes read or -1 on error.
 */
int get_possible_cpu_mask_from_sysfs(char *buf, size_t max_bytes)
	__attribute__((visibility("hidden")));

/*
 * Get the number of possible CPUs in the system from either
 * sysconf(_SC_NPROCESSORS_CONF) or some other mechanism depending on the libc.
 *
 * Returns the number of possible CPUs in the system or 0 on error.
 */
int get_num_possible_cpus_fallback(void)
	__attribute__((visibility("hidden")));

/*
 * Get the number of CPUs from the possible cpu mask.
 *
 * pmask: the mask to parse.
 * len: the len of the mask excluding '\0'.
 *
 * Returns the number of possible CPUs from the mask or 0 on error.
 */
int get_num_possible_cpus_from_mask(const char *pmask, size_t len)
	__attribute__((visibility("hidden")));

extern void _get_num_possible_cpus(void);

/*
 * Returns the total number of CPUs in the system. If the cache is not yet
 * initialized, get the value from "/sys/devices/system/cpu/possible" or
 * fallback to sysconf and cache it.
 *
 * If all methods fail, don't populate the cache and return 0.
 */
static inline
int num_possible_cpus(void)
{
	if (caa_unlikely(!__num_possible_cpus))
		_get_num_possible_cpus();

	return __num_possible_cpus;
}

#define for_each_possible_cpu(cpu)		\
	for ((cpu) = 0; (cpu) < num_possible_cpus(); (cpu)++)

#endif /* _LIBRINGBUFFER_SMP_H */
