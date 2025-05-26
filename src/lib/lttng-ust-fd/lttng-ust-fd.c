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
#include <dlfcn.h>
#include <errno.h>

#include <lttng/ust-common.h>
#include <lttng/ust-fd.h>

#include "common/macros.h"

#define LTTNG_UST_DLSYM_FAILED_PTR 0x1

static int (*__lttng_ust_fd_plibc_close)(int fd) = NULL;
static int (*__lttng_ust_fd_plibc_fclose)(FILE *stream) = NULL;
static int (*__lttng_ust_fd_plibc_close_range)(unsigned int first,
		unsigned int last, int flags) = NULL;

/*
 * Use dlsym to find the original libc close() symbol and store it in
 * __lttng_ust_fd_plibc_close.
 */
static
void *_lttng_ust_fd_init_plibc_close(void)
{
	if (__lttng_ust_fd_plibc_close == NULL) {
		__lttng_ust_fd_plibc_close = dlsym(RTLD_NEXT, "close");

		if (__lttng_ust_fd_plibc_close == NULL) {
			__lttng_ust_fd_plibc_close = (void *) LTTNG_UST_DLSYM_FAILED_PTR;
			fprintf(stderr, "%s\n", dlerror());
		}
	}

	return __lttng_ust_fd_plibc_close;
}

/*
 * Use dlsym to find the original libc fclose() symbol and store it in
 * __lttng_ust_fd_plibc_fclose.
 */
static
void *_lttng_ust_fd_init_plibc_fclose(void)
{
	if (__lttng_ust_fd_plibc_fclose == NULL) {
		__lttng_ust_fd_plibc_fclose = dlsym(RTLD_NEXT, "fclose");

		if (__lttng_ust_fd_plibc_fclose == NULL) {
			__lttng_ust_fd_plibc_fclose = (void *) LTTNG_UST_DLSYM_FAILED_PTR;
			fprintf(stderr, "%s\n", dlerror());
		}
	}

	return __lttng_ust_fd_plibc_fclose;
}

/*
 * Use dlsym to find the original libc close_range() symbol and store it
 * in __lttng_ust_fd_plibc_close_range. The close_range symbol only
 * appears in glibc 2.34, so it is considered optional.
 */
static
void *_lttng_ust_fd_init_plibc_close_range(void)
{
	if (__lttng_ust_fd_plibc_close_range == NULL) {
		__lttng_ust_fd_plibc_close_range = dlsym(RTLD_NEXT, "close_range");

		if (__lttng_ust_fd_plibc_close_range == NULL)
			__lttng_ust_fd_plibc_close_range = (void *) LTTNG_UST_DLSYM_FAILED_PTR;
	}

	return __lttng_ust_fd_plibc_close_range;
}

static
void _lttng_ust_fd_ctor(void)
	__attribute__((constructor));
static
void _lttng_ust_fd_ctor(void)
{
	lttng_ust_common_ctor();

	/*
	 * Initialize the function pointers to the original libc symbols in the
	 * constructor since close() has to stay async-signal-safe and as such,
	 * we can't call dlsym() in the override functions.
	 */
	(void) _lttng_ust_fd_init_plibc_close();
	(void) _lttng_ust_fd_init_plibc_fclose();
	(void) _lttng_ust_fd_init_plibc_close_range();
}

/*
 * Override the libc close() symbol with our own, allowing applications to
 * close arbitrary file descriptors. If the fd is owned by lttng-ust, return
 * -1, errno=EBADF instead of closing it.
 *
 * If dlsym failed to find the original libc close() symbol, return -1,
 * errno=ENOSYS.
 *
 * There is a short window before the library constructor has executed where
 * this wrapper could call dlsym() and thus not be async-signal-safe.
 */
int close(int fd)
{
	/*
	 * We can't retry dlsym here since close is async-signal-safe.
	 */
	if (_lttng_ust_fd_init_plibc_close() == (void *) LTTNG_UST_DLSYM_FAILED_PTR) {
		errno = ENOSYS;
		return -1;
	}

	return lttng_ust_safe_close_fd(fd, __lttng_ust_fd_plibc_close);
}

/*
 * Override the libc fclose() symbol with our own, allowing applications to
 * close arbitrary streams. If the fd is owned by lttng-ust, return -1,
 * errno=EBADF instead of closing it.
 *
 * If dlsym failed to find the original libc close() symbol, return -1,
 * errno=ENOSYS.
 *
 * There is a short window before the library constructor has executed where
 * this wrapper could call dlsym() and thus not be async-signal-safe.
 *
 * Note: fcloseall() is not an issue because it closes only the streams it
 * knows about, which differs from the problems caused by gnulib
 * close_stdout(), which does an explicit fclose(stdout).
 */
int fclose(FILE *stream)
{
	if (_lttng_ust_fd_init_plibc_fclose() == (void *) LTTNG_UST_DLSYM_FAILED_PTR) {
		errno = ENOSYS;
		return -1;
	}

	return lttng_ust_safe_fclose_stream(stream,
			__lttng_ust_fd_plibc_fclose);
}

/* Old libc headers don't contain a close_range() declaration. */
int close_range(unsigned int first, unsigned int last, int flags);

/*
 * Override the libc close_range() symbol with our own, allowing
 * applications to close arbitrary file descriptors. If the fd is owned
 * by lttng-ust, return -1, errno=EBADF instead of closing it.
 *
 * If dlsym failed to find the original libc close_range() symbol,
 * return -1, errno=ENOSYS.
 *
 * There is a short window before the library constructor has executed where
 * this wrapper could call dlsym() and thus not be async-signal-safe.
 */
int close_range(unsigned int first, unsigned int last, int flags)
{
	/*
	 * We can't retry dlsym here since close is async-signal-safe.
	 */
	if (_lttng_ust_fd_init_plibc_close_range() == (void *) LTTNG_UST_DLSYM_FAILED_PTR) {
		errno = ENOSYS;
		return -1;
	}

	return lttng_ust_safe_close_range_fd(first, last, flags, __lttng_ust_fd_plibc_close_range);
}

#if defined(__sun__) || defined(__FreeBSD__)
/* Solaris and FreeBSD. */
void closefrom(int lowfd)
{
	if (_lttng_ust_fd_init_plibc_close() == (void *) LTTNG_UST_DLSYM_FAILED_PTR) {
		return;
	}

	(void) lttng_ust_safe_closefrom_fd(lowfd, __lttng_ust_fd_plibc_close);
}
#elif defined(__NetBSD__) || defined(__OpenBSD__)
/* NetBSD and OpenBSD. */
int closefrom(int lowfd)
{
	if (_lttng_ust_fd_init_plibc_close() == (void *) LTTNG_UST_DLSYM_FAILED_PTR) {
		errno = ENOSYS;
		return -1;
	}

	return lttng_ust_safe_closefrom_fd(lowfd, __lttng_ust_fd_plibc_close);
}
#else
/* As far as we know, this OS does not implement closefrom. */
#endif
