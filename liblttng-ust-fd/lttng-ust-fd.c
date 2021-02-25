/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2016  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#define _LGPL_SOURCE
#include <limits.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <ust-fd.h>
#include <dlfcn.h>

#include <ust-helper.h>
#include "usterr-signal-safe.h"

static int (*__lttng_ust_fd_plibc_close)(int fd);
static int (*__lttng_ust_fd_plibc_fclose)(FILE *stream);

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

static
int _lttng_ust_fd_libc_fclose(FILE *stream)
{
	if (!__lttng_ust_fd_plibc_fclose) {
		__lttng_ust_fd_plibc_fclose = dlsym(RTLD_NEXT, "fclose");
		if (!__lttng_ust_fd_plibc_fclose) {
			fprintf(stderr, "%s\n", dlerror());
			return -1;
		}
	}
	return lttng_ust_safe_fclose_stream(stream,
			__lttng_ust_fd_plibc_fclose);
}

int close(int fd)
{
	return _lttng_ust_fd_libc_close(fd);
}

/*
 * Note: fcloseall() is not an issue because it fcloses only the
 * streams it knows about, which differs from the problems caused by
 * gnulib close_stdout(), which does an explicit fclose(stdout).
 */
int fclose(FILE *stream)
{
	return _lttng_ust_fd_libc_fclose(stream);
}

#if defined(__sun__) || defined(__FreeBSD__)
/* Solaris and FreeBSD. */
void closefrom(int lowfd)
{
	(void) lttng_ust_safe_closefrom_fd(lowfd, __lttng_ust_fd_plibc_close);
}
#elif defined(__NetBSD__) || defined(__OpenBSD__)
/* NetBSD and OpenBSD. */
int closefrom(int lowfd)
{
	return lttng_ust_safe_closefrom_fd(lowfd, __lttng_ust_fd_plibc_close);
}
#else
/* As far as we know, this OS does not implement closefrom. */
#endif
