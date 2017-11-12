/*
 * Copyright (C)  2016 - Aravind HT <aravind.ht@gmail.com>
 *                2016 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <fcntl.h>
#include <pthread.h>
#include <urcu/compiler.h>
#include <urcu/tls-compat.h>
#include <urcu/system.h>

#include <ust-fd.h>
#include <helper.h>
#include <lttng/ust-error.h>
#include <usterr-signal-safe.h>

#include "../liblttng-ust/compat.h"

/* Operations on the fd set. */
#define IS_FD_VALID(fd)			((fd) >= 0 && (fd) < lttng_ust_max_fd)
#define GET_FD_SET_FOR_FD(fd, fd_sets)	(&((fd_sets)[(fd) / FD_SETSIZE]))
#define CALC_INDEX_TO_SET(fd)		((fd) % FD_SETSIZE)

/* Check fd validity before calling these. */
#define ADD_FD_TO_SET(fd, fd_sets)	\
		FD_SET(CALC_INDEX_TO_SET(fd), GET_FD_SET_FOR_FD(fd, fd_sets))
#define IS_FD_SET(fd, fd_sets)		\
		FD_ISSET(CALC_INDEX_TO_SET(fd), GET_FD_SET_FOR_FD(fd, fd_sets))
#define DEL_FD_FROM_SET(fd, fd_sets)	\
		FD_CLR(CALC_INDEX_TO_SET(fd), GET_FD_SET_FOR_FD(fd, fd_sets))

/*
 * Protect the lttng_fd_set. Nests within the ust_lock, and therefore
 * within the libc dl lock. Therefore, we need to fixup the TLS before
 * nesting into this lock.
 */
static pthread_mutex_t ust_safe_guard_fd_mutex = PTHREAD_MUTEX_INITIALIZER;
/*
 * Track whether we are within lttng-ust or application, for close
 * system call override by LD_PRELOAD library.
 */
static DEFINE_URCU_TLS(int, thread_fd_tracking);

/* fd_set used to book keep fd being used by lttng-ust. */
static fd_set *lttng_fd_set;
static int lttng_ust_max_fd;
static int num_fd_sets;
static int init_done;

/*
 * Force a read (imply TLS fixup for dlopen) of TLS variables.
 */
void lttng_ust_fixup_fd_tracker_tls(void)
{
	asm volatile ("" : : "m" (URCU_TLS(thread_fd_tracking)));
}

/*
 * Allocate the fd set array based on the hard limit set for this
 * process. This will be called during the constructor execution
 * and will also be called in the child after fork via lttng_ust_init.
 */
void lttng_ust_init_fd_tracker(void)
{
	struct rlimit rlim;
	int i;

	if (CMM_LOAD_SHARED(init_done))
		return;

	memset(&rlim, 0, sizeof(rlim));
	/* Get the current possible max number of fd for this process. */
	if (getrlimit(RLIMIT_NOFILE, &rlim) < 0)
		abort();
	/*
	 * FD set array size determined using the hard limit. Even if
	 * the process wishes to increase its limit using setrlimit, it
	 * can only do so with the softlimit which will be less than the
	 * hard limit.
	 */
	lttng_ust_max_fd = rlim.rlim_max;
	num_fd_sets = lttng_ust_max_fd / FD_SETSIZE;
	if (lttng_ust_max_fd % FD_SETSIZE)
		++num_fd_sets;
	if (lttng_fd_set != NULL) {
		free(lttng_fd_set);
		lttng_fd_set = NULL;
	}
	lttng_fd_set = malloc(num_fd_sets * (sizeof(fd_set)));
	if (!lttng_fd_set)
		abort();
	for (i = 0; i < num_fd_sets; i++)
		FD_ZERO((&lttng_fd_set[i]));
	CMM_STORE_SHARED(init_done, 1);
}

void lttng_ust_lock_fd_tracker(void)
{
	URCU_TLS(thread_fd_tracking) = 1;
	/*
	 * Ensure the compiler don't move the store after the close()
	 * call in case close() would be marked as leaf.
	 */
	cmm_barrier();
	pthread_mutex_lock(&ust_safe_guard_fd_mutex);
}

void lttng_ust_unlock_fd_tracker(void)
{
	pthread_mutex_unlock(&ust_safe_guard_fd_mutex);
	/*
	 * Ensure the compiler don't move the store before the close()
	 * call, in case close() would be marked as leaf.
	 */
	cmm_barrier();
	URCU_TLS(thread_fd_tracking) = 0;
}

/*
 * Needs to be called with ust_safe_guard_fd_mutex held when opening the fd.
 * Has strict checking of fd validity.
 */
void lttng_ust_add_fd_to_tracker(int fd)
{
	/*
	 * Ensure the tracker is initialized when called from
	 * constructors.
	 */
	lttng_ust_init_fd_tracker();

	assert(URCU_TLS(thread_fd_tracking));
	/* Trying to add an fd which we can not accommodate. */
	assert(IS_FD_VALID(fd));
	/* Setting an fd thats already set. */
	assert(!IS_FD_SET(fd, lttng_fd_set));

	ADD_FD_TO_SET(fd, lttng_fd_set);
}

/*
 * Needs to be called with ust_safe_guard_fd_mutex held when opening the fd.
 * Has strict checking for fd validity.
 */
void lttng_ust_delete_fd_from_tracker(int fd)
{
	/*
	 * Ensure the tracker is initialized when called from
	 * constructors.
	 */
	lttng_ust_init_fd_tracker();

	assert(URCU_TLS(thread_fd_tracking));
	/* Not a valid fd. */
	assert(IS_FD_VALID(fd));
	/* Deleting an fd which was not set. */
	assert(IS_FD_SET(fd, lttng_fd_set));

	DEL_FD_FROM_SET(fd, lttng_fd_set);
}

/*
 * Interface allowing applications to close arbitrary file descriptors.
 * We check if it is owned by lttng-ust, and return -1, errno=EBADF
 * instead of closing it if it is the case.
 */
int lttng_ust_safe_close_fd(int fd, int (*close_cb)(int fd))
{
	int ret = 0;

	lttng_ust_fixup_fd_tracker_tls();

	/*
	 * Ensure the tracker is initialized when called from
	 * constructors.
	 */
	lttng_ust_init_fd_tracker();

	/*
	 * If called from lttng-ust, we directly call close without
	 * validating whether the FD is part of the tracked set.
	 */
	if (URCU_TLS(thread_fd_tracking))
		return close_cb(fd);

	lttng_ust_lock_fd_tracker();
	if (IS_FD_VALID(fd) && IS_FD_SET(fd, lttng_fd_set)) {
		ret = -1;
		errno = EBADF;
	} else {
		ret = close_cb(fd);
	}
	lttng_ust_unlock_fd_tracker();

	return ret;
}

/*
 * Interface allowing applications to close arbitrary streams.
 * We check if it is owned by lttng-ust, and return -1, errno=EBADF
 * instead of closing it if it is the case.
 */
int lttng_ust_safe_fclose_stream(FILE *stream, int (*fclose_cb)(FILE *stream))
{
	int ret = 0, fd;

	lttng_ust_fixup_fd_tracker_tls();

	/*
	 * Ensure the tracker is initialized when called from
	 * constructors.
	 */
	lttng_ust_init_fd_tracker();

	/*
	 * If called from lttng-ust, we directly call fclose without
	 * validating whether the FD is part of the tracked set.
	 */
	if (URCU_TLS(thread_fd_tracking))
		return fclose_cb(stream);

	fd = fileno(stream);

	lttng_ust_lock_fd_tracker();
	if (IS_FD_VALID(fd) && IS_FD_SET(fd, lttng_fd_set)) {
		ret = -1;
		errno = EBADF;
	} else {
		ret = fclose_cb(stream);
	}
	lttng_ust_unlock_fd_tracker();

	return ret;
}

#ifdef __OpenBSD__
static void set_close_success(int *p)
{
	*p = 1;
}
static int test_close_success(const int *p)
{
	return *p;
}
#else
static void set_close_success(int *p  __attribute__((unused)))
{
}
static int test_close_success(const int *p __attribute__((unused)))
{
	return 1;
}
#endif

/*
 * Implement helper for closefrom() override.
 */
int lttng_ust_safe_closefrom_fd(int lowfd, int (*close_cb)(int fd))
{
	int ret = 0, close_success = 0, i;

	lttng_ust_fixup_fd_tracker_tls();

	/*
	 * Ensure the tracker is initialized when called from
	 * constructors.
	 */
	lttng_ust_init_fd_tracker();

	if (lowfd < 0) {
		/*
		 * NetBSD return EBADF if fd is invalid.
		 */
		errno = EBADF;
		ret = -1;
		goto end;
	}
	/*
	 * If called from lttng-ust, we directly call close without
	 * validating whether the FD is part of the tracked set.
	 */
	if (URCU_TLS(thread_fd_tracking)) {
		for (i = lowfd; i < lttng_ust_max_fd; i++) {
			if (close_cb(i) < 0) {
				switch (errno) {
				case EBADF:
					continue;
				case EINTR:
				default:
					ret = -1;
					goto end;
				}
			}
			set_close_success(&close_success);
		}
	} else {
		lttng_ust_lock_fd_tracker();
		for (i = lowfd; i < lttng_ust_max_fd; i++) {
			if (IS_FD_VALID(i) && IS_FD_SET(i, lttng_fd_set))
				continue;
			if (close_cb(i) < 0) {
				switch (errno) {
				case EBADF:
					continue;
				case EINTR:
				default:
					ret = -1;
					lttng_ust_unlock_fd_tracker();
					goto end;
				}
			}
			set_close_success(&close_success);
		}
		lttng_ust_unlock_fd_tracker();
	}
	if (!test_close_success(&close_success)) {
		/*
		 * OpenBSD return EBADF if fd is greater than all open
		 * file descriptors.
		 */
		ret = -1;
		errno = EBADF;
	}
end:
	return ret;
}
