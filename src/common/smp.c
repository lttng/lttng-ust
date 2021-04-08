/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2019 Michael Jeanson <mjeanson@efficios.com>
 */

#define _LGPL_SOURCE
#include <unistd.h>
#include <pthread.h>

#include <urcu/compiler.h>

#include "common/smp.h"

static int num_possible_cpus_cache;

#if (defined(__GLIBC__) || defined( __UCLIBC__))
static void _get_num_possible_cpus(void)
{
	int result;

	/* On Linux, when some processors are offline
	 * _SC_NPROCESSORS_CONF counts the offline
	 * processors, whereas _SC_NPROCESSORS_ONLN
	 * does not. If we used _SC_NPROCESSORS_ONLN,
	 * getcpu() could return a value greater than
	 * this sysconf, in which case the arrays
	 * indexed by processor would overflow.
	 */
	result = sysconf(_SC_NPROCESSORS_CONF);
	if (result == -1)
		return;
	num_possible_cpus_cache = result;
}

#else

/*
 * The MUSL libc implementation of the _SC_NPROCESSORS_CONF sysconf does not
 * return the number of configured CPUs in the system but relies on the cpu
 * affinity mask of the current task.
 *
 * So instead we use a strategy similar to GLIBC's, counting the cpu
 * directories in "/sys/devices/system/cpu" and fallback on the value from
 * sysconf if it fails.
 */

#include <dirent.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define __max(a,b) ((a)>(b)?(a):(b))

static void _get_num_possible_cpus(void)
{
	int result, count = 0;
	DIR *cpudir;
	struct dirent *entry;

	cpudir = opendir("/sys/devices/system/cpu");
	if (cpudir == NULL)
		goto end;

	/*
	 * Count the number of directories named "cpu" followed by and
	 * integer. This is the same strategy as glibc uses.
	 */
	while ((entry = readdir(cpudir))) {
		if (entry->d_type == DT_DIR &&
			strncmp(entry->d_name, "cpu", 3) == 0) {

			char *endptr;
			unsigned long cpu_num;

			cpu_num = strtoul(entry->d_name + 3, &endptr, 10);
			if ((cpu_num < ULONG_MAX) && (endptr != entry->d_name + 3)
					&& (*endptr == '\0')) {
				count++;
			}
		}
	}

end:
	/*
	 * Get the sysconf value as a fallback. Keep the highest number.
	 */
	result = __max(sysconf(_SC_NPROCESSORS_CONF), count);

	/*
	 * If both methods failed, don't store the value.
	 */
	if (result < 1)
		return;
	num_possible_cpus_cache = result;
}
#endif

/*
 * Returns the total number of CPUs in the system. If the cache is not yet
 * initialized, get the value from the system through sysconf and cache it.
 *
 * If the sysconf call fails, don't populate the cache and return 0.
 */
int num_possible_cpus(void)
{
	if (caa_unlikely(!num_possible_cpus_cache))
		_get_num_possible_cpus();

	return num_possible_cpus_cache;
}
