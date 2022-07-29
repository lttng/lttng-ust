/*
 * libringbuffer/smp.c
 *
 * Copyright (C) 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2019 Michael Jeanson <mjeanson@efficios.com>
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

#define _GNU_SOURCE
#define _LGPL_SOURCE
#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>

#include "smp.h"
#include "usterr-signal-safe.h"

#define __max(a,b) ((a)>(b)?(a):(b))

int __num_possible_cpus;

/*
 * As a fallback to parsing the CPU mask in "/sys/devices/system/cpu/possible",
 * iterate on all the folders in "/sys/devices/system/cpu" that start with
 * "cpu" followed by an integer, keep the highest CPU id encountered during
 * this iteration and add 1 to get a number of CPUs.
 *
 * Then get the value from sysconf(_SC_NPROCESSORS_CONF) as a fallback and
 * return the highest one.
 *
 * On Linux, using the value from sysconf can be unreliable since the way it
 * counts CPUs varies between C libraries and even between versions of the same
 * library. If we used it directly, getcpu() could return a value greater than
 * this sysconf, in which case the arrays indexed by processor would overflow.
 *
 * As another example, the MUSL libc implementation of the _SC_NPROCESSORS_CONF
 * sysconf does not return the number of configured CPUs in the system but
 * relies on the cpu affinity mask of the current task.
 *
 * Returns 0 or less on error.
 */
int get_num_possible_cpus_fallback(void)
{
	long max_cpuid = -1;

	DIR *cpudir;
	struct dirent *entry;

	cpudir = opendir("/sys/devices/system/cpu");
	if (cpudir == NULL)
		goto end;

	/*
	 * Iterate on all directories named "cpu" followed by an integer.
	 */
	while ((entry = readdir(cpudir))) {
		if (entry->d_type == DT_DIR &&
			strncmp(entry->d_name, "cpu", 3) == 0) {

			char *endptr;
			long cpu_id;

			cpu_id = strtol(entry->d_name + 3, &endptr, 10);
			if ((cpu_id < LONG_MAX) && (endptr != entry->d_name + 3)
					&& (*endptr == '\0')) {
				if (cpu_id > max_cpuid)
					max_cpuid = cpu_id;
			}
		}
	}

	if (closedir(cpudir))
		PERROR("closedir");

	/*
	 * If the max CPU id is out of bound, set it to -1 so it results in a
	 * CPU num of 0.
	 */
	if (max_cpuid < 0 || max_cpuid > INT_MAX)
		max_cpuid = -1;

end:
	/*
	 * Get the sysconf value as a last resort. Keep the highest number.
	 */
	return __max(sysconf(_SC_NPROCESSORS_CONF), max_cpuid + 1);
}

/*
 * Get the CPU possible mask string from sysfs.
 *
 * buf: the buffer where the mask will be read.
 * max_bytes: the maximum number of bytes to write in the buffer.
 *
 * Returns the number of bytes read or -1 on error.
 */
int get_possible_cpu_mask_from_sysfs(char *buf, size_t max_bytes)
{
	ssize_t bytes_read = 0;
	size_t total_bytes_read = 0;
	int fd = -1, ret = -1;

	if (buf == NULL)
		goto end;

	fd = open("/sys/devices/system/cpu/possible", O_RDONLY);
	if (fd < 0)
		goto end;

	do {
		bytes_read = read(fd, buf + total_bytes_read,
				max_bytes - total_bytes_read);

		if (bytes_read < 0) {
			if (errno == EINTR) {
				continue;	/* retry operation */
			} else {
				goto end;
			}
		}

		total_bytes_read += bytes_read;
		assert(total_bytes_read <= max_bytes);
	} while (max_bytes > total_bytes_read && bytes_read > 0);

	/*
	 * Make sure the mask read is a null terminated string.
	 */
	if (total_bytes_read < max_bytes)
		buf[total_bytes_read] = '\0';
	else
		buf[max_bytes - 1] = '\0';

	if (total_bytes_read > INT_MAX)
		goto end;

	ret = (int) total_bytes_read;

end:
	if (fd >= 0 && close(fd) < 0)
		PERROR("close");

	return ret;
}

/*
 * Get the number of CPUs from the possible cpu mask.
 *
 * pmask: the mask to parse.
 * len: the len of the mask excluding '\0'.
 *
 * Returns the number of possible CPUs from the mask or 0 on error.
 */
int get_num_possible_cpus_from_mask(const char *pmask, size_t len)
{
	ssize_t i;
	unsigned long cpu_index;
	char *endptr;

	/* We need at least one char to read */
	if (len < 1)
		goto error;

	/* Start from the end to read the last CPU index. */
	for (i = len - 1; i > 0; i--) {
		/* Break when we hit the first separator. */
		if ((pmask[i] == ',') || (pmask[i] == '-')) {
			i++;
			break;
		}
	}

	cpu_index = strtoul(&pmask[i], &endptr, 10);

	/*
	 * If we read a CPU index, increment it by one to return a number of
	 * CPUs.
	 */
	if ((&pmask[i] != endptr) && (cpu_index < INT_MAX))
		return (int) cpu_index + 1;

error:
	return 0;
}

void _get_num_possible_cpus(void)
{
	int ret;
	char buf[LTTNG_UST_CPUMASK_SIZE];

	/* Get the possible cpu mask from sysfs, fallback to sysconf. */
	ret = get_possible_cpu_mask_from_sysfs((char *) &buf, LTTNG_UST_CPUMASK_SIZE);
	if (ret <= 0)
		goto fallback;

	/* Parse the possible cpu mask, on failure fallback to sysconf. */
	ret = get_num_possible_cpus_from_mask((char *) &buf, ret);
	if (ret > 0)
		goto end;

fallback:
	/* Fallback to sysconf. */
	ret = get_num_possible_cpus_fallback();

end:
	/* If all methods failed, don't store the value. */
	if (ret < 1)
		return;

	__num_possible_cpus = ret;
}
