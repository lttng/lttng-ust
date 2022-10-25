/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _UST_COMMON_SMP_H
#define _UST_COMMON_SMP_H

#define LTTNG_UST_CPUMASK_SIZE 4096

/*
 * Get a CPU mask string from sysfs.
 *
 * buf: the buffer where the mask will be read.
 * max_bytes: the maximum number of bytes to write in the buffer.
 * path: file path to read the mask from.
 *
 * Returns the number of bytes read or -1 on error.
 */
int get_cpu_mask_from_sysfs(char *buf, size_t max_bytes, const char *path)
	__attribute__((visibility("hidden")));

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
 * Get the highest CPU id from sysfs.
 *
 * Iterate on all the folders in "/sys/devices/system/cpu" that start with
 * "cpu" followed by an integer, keep the highest CPU id encountered during
 * this iteration and add 1 to get a number of CPUs.
 *
 * Returns the highest CPU id, or -1 on error.
 */
int get_max_cpuid_from_sysfs(void)
	__attribute__((visibility("hidden")));

int _get_max_cpuid_from_sysfs(const char *path)
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
 * Get the highest CPU id from a CPU mask.
 *
 * pmask: the mask to parse.
 * len: the len of the mask excluding '\0'.
 *
 * Returns the highest CPU id from the mask or -1 on error.
 */
int get_max_cpuid_from_mask(const char *pmask, size_t len)
	__attribute__((visibility("hidden")));

/*
 * Returns the length of an array that could contain a per-CPU element for each
 * possible CPU id for the lifetime of the process.
 *
 * We currently assume CPU ids are contiguous up the maximum CPU id.
 *
 * If the cache is not yet initialized, get the value from
 * "/sys/devices/system/cpu/possible" or fallback to sysconf and cache it.
 *
 * If all methods fail, don't populate the cache and return 0.
 */
int get_possible_cpus_array_len(void)
	__attribute__((visibility("hidden")));

#define for_each_possible_cpu(cpu)		\
	for ((cpu) = 0; (cpu) < get_possible_cpus_array_len(); (cpu)++)

#endif /* _UST_COMMON_SMP_H */
