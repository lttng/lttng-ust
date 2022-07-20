/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _UST_COMMON_SMP_H
#define _UST_COMMON_SMP_H

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

/*
 * Returns the total number of CPUs in the system. If the cache is not yet
 * initialized, get the value from "/sys/devices/system/cpu/possible" or
 * fallback to sysconf and cache it.
 *
 * If all methods fail, don't populate the cache and return 0.
 */
int num_possible_cpus(void)
	__attribute__((visibility("hidden")));

#define for_each_possible_cpu(cpu)		\
	for ((cpu) = 0; (cpu) < num_possible_cpus(); (cpu)++)

#endif /* _UST_COMMON_SMP_H */
