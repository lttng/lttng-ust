/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2019 Michael Jeanson <mjeanson@efficios.com>
 */

#define _LGPL_SOURCE
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>

#include <urcu/compiler.h>

#include "common/align.h"
#include "common/logging.h"
#include "common/smp.h"

static int num_possible_cpus_cache;

#if (defined(__GLIBC__) || defined( __UCLIBC__))
int get_num_possible_cpus_fallback(void)
{
	/* On Linux, when some processors are offline
	 * _SC_NPROCESSORS_CONF counts the offline
	 * processors, whereas _SC_NPROCESSORS_ONLN
	 * does not. If we used _SC_NPROCESSORS_ONLN,
	 * getcpu() could return a value greater than
	 * this sysconf, in which case the arrays
	 * indexed by processor would overflow.
	 */
	return sysconf(_SC_NPROCESSORS_CONF);
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

int get_num_possible_cpus_fallback(void)
{
	int count = 0;
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
	return __max(sysconf(_SC_NPROCESSORS_CONF), count);
}
#endif

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

static void _get_num_possible_cpus(void)
{
	int ret;
	int buf_len = LTTNG_UST_PAGE_SIZE;
	char buf[buf_len];

	/* Get the possible cpu mask from sysfs, fallback to sysconf. */
	ret = get_possible_cpu_mask_from_sysfs((char *) &buf, buf_len);
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

	num_possible_cpus_cache = ret;
}

/*
 * Returns the total number of CPUs in the system. If the cache is not yet
 * initialized, get the value from "/sys/devices/system/cpu/possible" or
 * fallback to sysconf and cache it.
 *
 * If all methods fail, don't populate the cache and return 0.
 */
int num_possible_cpus(void)
{
	if (caa_unlikely(!num_possible_cpus_cache))
		_get_num_possible_cpus();

	return num_possible_cpus_cache;
}
