/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2016 Aravind HT <aravind.ht@gmail.com>
 * Copyright (C) 2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <urcu/compiler.h>
#include <urcu/hlist.h>
#include <urcu/tls-compat.h>
#include <urcu/system.h>

#include "common/ust-fd.h"
#include "common/macros.h"
#include <lttng/ust-error.h>
#include <lttng/ust-cancelstate.h>
#include "common/logging.h"

#include "lib/lttng-ust-common/fd-tracker.h"

/* Hash table for tracking fds used by lttng-ust. */
#define FD_TRACKER_HT_BITS	10U
#define FD_TRACKER_HT_SIZE	(1U << FD_TRACKER_HT_BITS)

#define IS_FD_STD(fd)		((fd) >= 0 && (fd) <= STDERR_FILENO)

struct lttng_fd_entry {
	struct cds_hlist_node hlist;
	int fd;
};

/*
 * Protect fd_tracker_ht. Nests within the ust_lock, and therefore within the
 * libc dl lock. Therefore, we need to allocate the TLS before nesting into this
 * lock.
 *
 * The ust_safe_guard_fd_mutex nests within the ust_mutex. This mutex
 * is also held across fork.
 */
static pthread_mutex_t ust_safe_guard_fd_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * Track whether we are within lttng-ust or application, for close
 * system call override by LD_PRELOAD library. This also tracks whether
 * we are invoking close() from a signal handler nested on an
 * application thread.
 */
static DEFINE_URCU_TLS(int, ust_fd_mutex_nest);

/* Hash table used to book keep fd being used by lttng-ust. */
static struct cds_hlist_head fd_tracker_ht[FD_TRACKER_HT_SIZE];
static unsigned int lttng_ust_max_fd;
static int init_done;

static inline struct cds_hlist_head *fd_tracker_get_bucket(int fd)
{
	return &fd_tracker_ht[(unsigned int) fd % FD_TRACKER_HT_SIZE];
}

static struct lttng_fd_entry *fd_tracker_lookup(int fd)
{
	const struct cds_hlist_head *head;
	const struct cds_hlist_node *node;
	struct lttng_fd_entry *entry;

	if (caa_unlikely(fd < 0))
		return NULL;

	head = fd_tracker_get_bucket(fd);

	cds_hlist_for_each_entry(entry, node, head, hlist) {
		if (entry->fd == fd)
			return entry;
	}

	return NULL;
}

static inline bool fd_tracker_is_fd_tracked(int fd)
{
	return fd_tracker_lookup(fd) != NULL;
}

/*
 * Force a read (imply TLS allocation for dlopen) of TLS variables.
 */
void lttng_ust_fd_tracker_alloc_tls(void)
{
	__asm__ __volatile__ ("" : : "m" (URCU_TLS(ust_fd_mutex_nest)));
}

/*
 * Initialize the fd tracker hash table.
 * This will be called during the constructor execution
 * and will also be called in the child after fork via lttng_ust_init.
 */
void lttng_ust_fd_tracker_init(void)
{
	size_t i;

	if (CMM_LOAD_SHARED(init_done))
		return;


	if (!lttng_ust_max_fd) {
		struct rlimit rlim;

		if (getrlimit(RLIMIT_NOFILE, &rlim) < 0)
			abort();

		lttng_ust_max_fd = rlim.rlim_max;
	}

	for (i = 0; i < FD_TRACKER_HT_SIZE; ++i) {
		struct cds_hlist_head *head;
		struct cds_hlist_node *node, *tmp;
		struct lttng_fd_entry *entry;

		head = &fd_tracker_ht[i];

		/* Clear any existing entries (can happen after fork). */
		cds_hlist_for_each_entry_safe(entry, node, tmp, head, hlist) {
			cds_hlist_del(&entry->hlist);
			free(entry);
		}

		CDS_INIT_HLIST_HEAD(head);
	}

	CMM_STORE_SHARED(init_done, 1);
}

void lttng_ust_lock_fd_tracker(void)
{
	sigset_t sig_all_blocked, orig_mask;
	int ret;

	if (lttng_ust_cancelstate_disable_push()) {
		ERR("lttng_ust_cancelstate_disable_push");
	}
	sigfillset(&sig_all_blocked);
	ret = pthread_sigmask(SIG_SETMASK, &sig_all_blocked, &orig_mask);
	if (ret) {
		ERR("pthread_sigmask: %s", strerror(ret));
	}
	if (!URCU_TLS(ust_fd_mutex_nest)++) {
		/*
		 * Ensure the compiler don't move the store after the close()
		 * call in case close() would be marked as leaf.
		 */
		cmm_barrier();
		pthread_mutex_lock(&ust_safe_guard_fd_mutex);
	}
	ret = pthread_sigmask(SIG_SETMASK, &orig_mask, NULL);
	if (ret) {
		ERR("pthread_sigmask: %s", strerror(ret));
	}
}

void lttng_ust_unlock_fd_tracker(void)
{
	sigset_t sig_all_blocked, orig_mask;
	int ret;

	sigfillset(&sig_all_blocked);
	ret = pthread_sigmask(SIG_SETMASK, &sig_all_blocked, &orig_mask);
	if (ret) {
		ERR("pthread_sigmask: %s", strerror(ret));
	}
	/*
	 * Ensure the compiler don't move the store before the close()
	 * call, in case close() would be marked as leaf.
	 */
	cmm_barrier();
	if (!--URCU_TLS(ust_fd_mutex_nest)) {
		pthread_mutex_unlock(&ust_safe_guard_fd_mutex);
	}
	ret = pthread_sigmask(SIG_SETMASK, &orig_mask, NULL);
	if (ret) {
		ERR("pthread_sigmask: %s", strerror(ret));
	}
	if (lttng_ust_cancelstate_disable_pop()) {
		ERR("lttng_ust_cancelstate_disable_pop");
	}
}

static int dup_std_fd(int fd)
{
	int ret, i;
	int fd_to_close[STDERR_FILENO + 1];
	int fd_to_close_count = 0;
	int dup_cmd = F_DUPFD; /* Default command */
	int fd_valid = -1;

	if (!(IS_FD_STD(fd))) {
		/* Should not be here */
		ret = -1;
		goto error;
	}

	/* Check for FD_CLOEXEC flag */
	ret = fcntl(fd, F_GETFD);
	if (ret < 0) {
		PERROR("fcntl on f_getfd");
		ret = -1;
		goto error;
	}

	if (ret & FD_CLOEXEC) {
		dup_cmd = F_DUPFD_CLOEXEC;
	}

	/* Perform dup */
	for (i = 0; i < STDERR_FILENO + 1; i++) {
		ret = fcntl(fd, dup_cmd, 0);
		if (ret < 0) {
			PERROR("fcntl dup fd");
			goto error;
		}

		if (!(IS_FD_STD(ret))) {
			/* fd is outside of STD range, use it. */
			fd_valid = ret;
			/* Close fd received as argument. */
			fd_to_close[i] = fd;
			fd_to_close_count++;
			break;
		}

		fd_to_close[i] = ret;
		fd_to_close_count++;
	}

	/* Close intermediary fds */
	for (i = 0; i < fd_to_close_count; i++) {
		ret = close(fd_to_close[i]);
		if (ret) {
			PERROR("close on temporary fd: %d.", fd_to_close[i]);
			/*
			 * Not using an abort here would yield a complicated
			 * error handling for the caller. If a failure occurs
			 * here, the system is already in a bad state.
			 */
			abort();
		}
	}

	ret = fd_valid;
error:
	return ret;
}

static void fd_tracker_add(struct lttng_fd_entry *entry)
{
	struct cds_hlist_head *head;

	head = fd_tracker_get_bucket(entry->fd);
	cds_hlist_add_head(&entry->hlist, head);
}

/*
 * Needs to be called with ust_safe_guard_fd_mutex held when opening the fd.
 * Has strict checking of fd validity.
 *
 * If fd <= 2, dup the fd until fd > 2. This enables us to bypass
 * problems that can be encountered if UST uses stdin, stdout, stderr
 * fds for internal use (daemon etc.). This can happen if the
 * application closes either of those file descriptors. Intermediary fds
 * are closed as needed.
 *
 * Return -1 on error.
 *
 */
int lttng_ust_add_fd_to_tracker(int fd)
{
	struct lttng_fd_entry *entry = NULL;

	if (caa_unlikely(fd < 0))
		return -EBADF;

	/*
	 * Ensure the tracker is initialized when called from
	 * constructors.
	 */
	lttng_ust_fd_tracker_init();
	assert(URCU_TLS(ust_fd_mutex_nest));

	entry = zmalloc(sizeof(*entry));
	if (!entry)
		return -ENOMEM;

	if (IS_FD_STD(fd)) {
		fd = dup_std_fd(fd);
		if (fd < 0) {
			free(entry);
			goto end;
		}
	}

	/* Setting an fd that's already set. */
	assert(!fd_tracker_is_fd_tracked(fd));

	entry->fd = fd;

	fd_tracker_add(entry);
end:
	return fd;
}

static void fd_tracker_delete(struct lttng_fd_entry *entry)
{
	cds_hlist_del(&entry->hlist);
	free(entry);
}

/*
 * Needs to be called with ust_safe_guard_fd_mutex held when opening the fd.
 * Has strict checking for fd validity.
 */
void lttng_ust_delete_fd_from_tracker(int fd)
{
	struct lttng_fd_entry *entry;

	/*
	 * Ensure the tracker is initialized when called from
	 * constructors.
	 */
	lttng_ust_fd_tracker_init();

	assert(URCU_TLS(ust_fd_mutex_nest));
	/* Deleting an fd which was not set. */
	entry = fd_tracker_lookup(fd);
	assert(entry);

	fd_tracker_delete(entry);
}

/*
 * Interface allowing applications to close arbitrary file descriptors.
 * We check if it is owned by lttng-ust, and return -1, errno=EBADF
 * instead of closing it if it is the case.
 */
int lttng_ust_safe_close_fd(int fd, int (*close_cb)(int fd))
{
	int ret = 0;

	lttng_ust_fd_tracker_alloc_tls();

	/*
	 * Ensure the tracker is initialized when called from
	 * constructors.
	 */
	lttng_ust_fd_tracker_init();

	/*
	 * If called from lttng-ust, we directly call close without
	 * validating whether the FD is part of the tracked set.
	 */
	if (URCU_TLS(ust_fd_mutex_nest))
		return close_cb(fd);

	lttng_ust_lock_fd_tracker();
	if (fd_tracker_is_fd_tracked(fd)) {
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

	lttng_ust_fd_tracker_alloc_tls();

	/*
	 * Ensure the tracker is initialized when called from
	 * constructors.
	 */
	lttng_ust_fd_tracker_init();

	/*
	 * If called from lttng-ust, we directly call fclose without
	 * validating whether the FD is part of the tracked set.
	 */
	if (URCU_TLS(ust_fd_mutex_nest))
		return fclose_cb(stream);

	fd = fileno(stream);

	lttng_ust_lock_fd_tracker();
	if (fd_tracker_is_fd_tracked(fd)) {
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
	int ret = 0, close_success = 0;

	lttng_ust_fd_tracker_alloc_tls();

	/*
	 * Ensure the tracker is initialized when called from
	 * constructors.
	 */
	lttng_ust_fd_tracker_init();

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
	if (URCU_TLS(ust_fd_mutex_nest)) {
		for (unsigned int i = lowfd; i < lttng_ust_max_fd; i++) {
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
		for (unsigned int i = lowfd; i < lttng_ust_max_fd; i++) {
			if (fd_tracker_is_fd_tracked(i))
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

/*
 * Implement helper for close_range() override.
 */
int lttng_ust_safe_close_range_fd(unsigned int first, unsigned int last, int flags,
		int (*close_range_cb)(unsigned int first, unsigned int last, int flags))
{
	int ret = 0;

	lttng_ust_fd_tracker_alloc_tls();

	/*
	 * Ensure the tracker is initialized when called from
	 * constructors.
	 */
	lttng_ust_fd_tracker_init();

	if (first > last || last > INT_MAX) {
		ret = -1;
		errno = EINVAL;
		goto end;
	}
	/*
	 * If called from lttng-ust, we directly call close_range
	 * without validating whether the FD is part of the tracked set.
	 */
	if (URCU_TLS(ust_fd_mutex_nest)) {
		if (close_range_cb(first, last, flags) < 0) {
			ret = -1;
			goto end;
		}
	} else {
		unsigned int last_check = min_t(unsigned int,
						last,
						lttng_ust_max_fd);

		lttng_ust_lock_fd_tracker();
		for (unsigned int i = first; i <= last_check; i++) {
			if (fd_tracker_is_fd_tracked(i))
				continue;
			if (close_range_cb(i, i, flags) < 0) {
				ret = -1;
				/* propagate errno from close_range_cb. */
				lttng_ust_unlock_fd_tracker();
				goto end;
			}
		}
		if (last > lttng_ust_max_fd) {
			if (close_range_cb(lttng_ust_max_fd + 1, last, flags) < 0) {
				ret = -1;
				lttng_ust_unlock_fd_tracker();
				goto end;
			}
		}
		lttng_ust_unlock_fd_tracker();
	}
end:
	return ret;
}
