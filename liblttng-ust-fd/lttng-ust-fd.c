/*
 * Copyright (C) 2016  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; version 2.1 of
 * the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#define _GNU_SOURCE
#define _LGPL_SOURCE
#include <limits.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <ust-fd.h>
#include <dlfcn.h>

#include <helper.h>
#include "usterr-signal-safe.h"

volatile enum ust_loglevel ust_loglevel;

static int (*__lttng_ust_fd_plibc_close)(int fd);

static
int _lttng_ust_fd_libc_close(int fd)
{
	if (!__lttng_ust_fd_plibc_close) {
		__lttng_ust_fd_plibc_close = dlsym(RTLD_NEXT, "close");
		if (!__lttng_ust_fd_plibc_close) {
			fprintf(stderr, "%s\n", dlerror());
			return -1;
		}
	}
	return lttng_ust_safe_close_fd(fd, __lttng_ust_fd_plibc_close);
}

int close(int fd)
{
	return _lttng_ust_fd_libc_close(fd);
}

#if defined(__sun__) || defined(__FreeBSD__)
/* Solaris and FreeBSD. */
void closefrom(int lowfd)
{
	(void) lttng_ust_safe_closefrom(lowfd, __lttng_ust_fd_plibc_close);
}
#elif defined(__NetBSD__) || defined(__OpenBSD__)
/* NetBSD and OpenBSD. */
int closefrom(int lowfd)
{
	return lttng_ust_safe_closefrom(lowfd, __lttng_ust_fd_plibc_close);
}
#else
/* As far as we know, this OS does not implement closefrom. */
#endif
