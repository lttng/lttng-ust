/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2009  Pierre-Marc Fournier
 * Copyright (C) 2011-2012  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

/* Has to be included first to override dlfcn.h */
#include <common/compat/dlfcn.h>

#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <signal.h>
#include <sched.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>

#include <pthread.h>

#include <lttng/ust-fork.h>

#include <urcu/uatomic.h>

#include "common/macros.h"

struct libc_pointer {
	void **procedure;
	const char *symbol;
};

#define DEFINE_LIBC_POINTER(name) { (void**)&plibc_## name, #name }

#ifdef __linux__

struct user_desc;

static int (*plibc_clone)(int (*fn)(void *), void *child_stack,
			int flags, void *arg, pid_t *ptid,
			struct user_desc *tls, pid_t *ctid) = NULL;

static int (*plibc_setns)(int fd, int nstype) = NULL;

static int (*plibc_setresgid)(gid_t rgid, gid_t egid, gid_t sgid) = NULL;

static int (*plibc_setresuid)(uid_t ruid, uid_t euid, uid_t suid) = NULL;

static int (*plibc_unshare)(int flags) = NULL;

#elif defined (__FreeBSD__)

static pid_t (*plibc_rfork)(int flags) = NULL;

#endif

static int (*plibc_daemon)(int nochdir, int noclose) = NULL;

static pid_t (*plibc_fork)(void) = NULL;

static int (*plibc_setegid)(gid_t egid) = NULL;

static int (*plibc_seteuid)(uid_t euid) = NULL;

static int (*plibc_setgid)(gid_t gid) = NULL;

static int (*plibc_setregid)(gid_t rgid, gid_t egid) = NULL;

static int (*plibc_setreuid)(uid_t ruid, uid_t euid) = NULL;

static int (*plibc_setuid)(uid_t uid) = NULL;

static void lttng_ust_fork_wrapper_ctor(void)
	__attribute__((constructor));

static pthread_mutex_t initialization_guard = PTHREAD_MUTEX_INITIALIZER;
static bool was_initialized = false;

/*
 * Must be called with initialization_guard held.
 */
static void initialize(void)
{
	const struct libc_pointer libc_pointers[] = {
#ifdef __linux__
		DEFINE_LIBC_POINTER(clone),
		DEFINE_LIBC_POINTER(setns),
		DEFINE_LIBC_POINTER(setresgid),
		DEFINE_LIBC_POINTER(setresuid),
		DEFINE_LIBC_POINTER(unshare),
#elif defined (__FreeBSD__)
		DEFINE_LIBC_POINTER(rfork),
#endif
		DEFINE_LIBC_POINTER(daemon),
		DEFINE_LIBC_POINTER(fork),
		DEFINE_LIBC_POINTER(setegid),
		DEFINE_LIBC_POINTER(seteuid),
		DEFINE_LIBC_POINTER(setgid),
		DEFINE_LIBC_POINTER(setregid),
		DEFINE_LIBC_POINTER(setreuid),
		DEFINE_LIBC_POINTER(setuid),
	};

	size_t k;

	for (k = 0; k < LTTNG_ARRAY_SIZE(libc_pointers); ++k) {
		void *procedure = dlsym(RTLD_NEXT, libc_pointers[k].symbol);

		if (NULL == procedure) {
			fprintf(stderr,
				"libustfork: unable to find \"%s\" symbol\n",
				libc_pointers[k].symbol);
			continue;
		}

		uatomic_set(libc_pointers[k].procedure, procedure);
	}
}

/*
 * Lazy initialization is required because it is possible for a shared library
 * to have a constructor that is executed before our constructor, which could
 * call some libc functions that we are wrapping.
 *
 * It is also possible for this library constructor to create a thread using the
 * raw system call. Therefore, the lazy initialization must be multi-thread safe.
 */
static void *lazy_initialize(void **pfunc)
{
	void *func = uatomic_read(pfunc);

	/*
	 * If *pfunc != NULL, then it is assumed that some thread has already
	 * called the initialization routine.
	 */
	if (caa_likely(func)) {
		goto out;
	}

	pthread_mutex_lock(&initialization_guard);
	if (!was_initialized) {
		initialize();
		was_initialized = true;
	}
	func = *pfunc;
	pthread_mutex_unlock(&initialization_guard);
out:
	return func;
}

#define LAZY_INITIALIZE_OR_NOSYS(ptr)			\
	({						\
		void *ret;				\
							\
		ret = lazy_initialize((void**)&(ptr));	\
		if (NULL == ret) {			\
			errno = ENOSYS;			\
			return -1;			\
		}					\
							\
		ret;					\
	})

static void lttng_ust_fork_wrapper_ctor(void)
{
	/*
	 * Using fork here because it is defined on all supported OS.
	 */
	(void) lazy_initialize((void**)&plibc_fork);
}

pid_t fork(void)
{
	sigset_t sigset;
	pid_t retval;
	int saved_errno;

	pid_t (*func)(void) = LAZY_INITIALIZE_OR_NOSYS(plibc_fork);

	lttng_ust_before_fork(&sigset);
	/* Do the real fork */
	retval = func();
	saved_errno = errno;
	if (retval == 0) {
		/* child */
		lttng_ust_after_fork_child(&sigset);
	} else {
		lttng_ust_after_fork_parent(&sigset);
	}
	errno = saved_errno;
	return retval;
}

int daemon(int nochdir, int noclose)
{
	sigset_t sigset;
	int retval;
	int saved_errno;

	int (*func)(int, int) = LAZY_INITIALIZE_OR_NOSYS(plibc_daemon);

	lttng_ust_before_fork(&sigset);
	/* Do the real daemon call */
	retval = func(nochdir, noclose);
	saved_errno = errno;
	if (retval == 0) {
		/* child, parent called _exit() directly */
		lttng_ust_after_fork_child(&sigset);
	} else {
		/* on error in the parent */
		lttng_ust_after_fork_parent(&sigset);
	}
	errno = saved_errno;
	return retval;
}

int setuid(uid_t uid)
{
	int retval;
	int saved_errno;

	int (*func)(uid_t) = LAZY_INITIALIZE_OR_NOSYS(plibc_setuid);

	/* Do the real setuid */
	retval = func(uid);
	saved_errno = errno;

	lttng_ust_after_setuid();

	errno = saved_errno;
	return retval;
}

int setgid(gid_t gid)
{
	int retval;
	int saved_errno;

	int (*func)(gid_t) = LAZY_INITIALIZE_OR_NOSYS(plibc_setgid);

	/* Do the real setgid */
	retval = func(gid);
	saved_errno = errno;

	lttng_ust_after_setgid();

	errno = saved_errno;
	return retval;
}

int seteuid(uid_t euid)
{
	int retval;
	int saved_errno;

	int (*func)(uid_t) = LAZY_INITIALIZE_OR_NOSYS(plibc_seteuid);

	/* Do the real seteuid */
	retval = func(euid);
	saved_errno = errno;

	lttng_ust_after_seteuid();

	errno = saved_errno;
	return retval;
}

int setegid(gid_t egid)
{
	int retval;
	int saved_errno;

	int (*func)(gid_t) = LAZY_INITIALIZE_OR_NOSYS(plibc_setegid);

	/* Do the real setegid */
	retval = func(egid);
	saved_errno = errno;

	lttng_ust_after_setegid();

	errno = saved_errno;
	return retval;
}

int setreuid(uid_t ruid, uid_t euid)
{
	int retval;
	int saved_errno;

	int (*func)(uid_t, uid_t) =
		LAZY_INITIALIZE_OR_NOSYS(plibc_setreuid);

	/* Do the real setreuid */
	retval = func(ruid, euid);
	saved_errno = errno;

	lttng_ust_after_setreuid();

	errno = saved_errno;
	return retval;
}

int setregid(gid_t rgid, gid_t egid)
{
	int retval;
	int saved_errno;

	int (*func)(gid_t, gid_t) = LAZY_INITIALIZE_OR_NOSYS(plibc_setregid);

	/* Do the real setregid */
	retval = func(rgid, egid);
	saved_errno = errno;

	lttng_ust_after_setregid();

	errno = saved_errno;
	return retval;
}

#ifdef __linux__

struct ustfork_clone_info {
	int (*fn)(void *);
	void *arg;
	sigset_t sigset;
};

static int clone_fn(void *arg)
{
	struct ustfork_clone_info *info = (struct ustfork_clone_info *) arg;

	/* clone is now done and we are in child */
	lttng_ust_after_fork_child(&info->sigset);
	return info->fn(info->arg);
}

int clone(int (*fn)(void *), void *child_stack, int flags, void *arg, ...)
{
	/* var args */
	pid_t *ptid;
	struct user_desc *tls;
	pid_t *ctid;
	/* end of var args */
	va_list ap;
	int retval;
	int saved_errno;

	va_start(ap, arg);
	ptid = va_arg(ap, pid_t *);
	tls = va_arg(ap, struct user_desc *);
	ctid = va_arg(ap, pid_t *);
	va_end(ap);

	int (*func)(int (*)(void *), void *, int , void *, pid_t *,
		    struct user_desc *, pid_t *) =
		LAZY_INITIALIZE_OR_NOSYS(plibc_clone);

	if (flags & CLONE_VM) {
		/*
		 * Creating a thread, no need to intervene, just pass on
		 * the arguments.
		 */
		retval = func(fn, child_stack, flags, arg, ptid,
			tls, ctid);
		saved_errno = errno;
	} else {
		/* Creating a real process, we need to intervene. */
		struct ustfork_clone_info info = { .fn = fn, .arg = arg };

		lttng_ust_before_fork(&info.sigset);
		retval = func(clone_fn, child_stack, flags, &info,
			ptid, tls, ctid);
		saved_errno = errno;
		/* The child doesn't get here. */
		lttng_ust_after_fork_parent(&info.sigset);
	}
	errno = saved_errno;
	return retval;
}

int setns(int fd, int nstype)
{
	int retval;
	int saved_errno;

	int (*func)(int, int) = LAZY_INITIALIZE_OR_NOSYS(plibc_setns);

	/* Do the real setns */
	retval = func(fd, nstype);
	saved_errno = errno;

	lttng_ust_after_setns();

	errno = saved_errno;
	return retval;
}

int unshare(int flags)
{
	int retval;
	int saved_errno;

	int (*func)(int) = LAZY_INITIALIZE_OR_NOSYS(plibc_unshare);

	/* Do the real setns */
	retval = func(flags);
	saved_errno = errno;

	lttng_ust_after_unshare();

	errno = saved_errno;
	return retval;
}

int setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	int retval;
	int saved_errno;

	int (*func)(uid_t, uid_t, uid_t) =
		LAZY_INITIALIZE_OR_NOSYS(plibc_setresuid);

	/* Do the real setresuid */
	retval = func(ruid, euid, suid);
	saved_errno = errno;

	lttng_ust_after_setresuid();

	errno = saved_errno;
	return retval;
}

int setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	int retval;
	int saved_errno;

	int (*func)(gid_t, gid_t, gid_t) =
		LAZY_INITIALIZE_OR_NOSYS(plibc_setresgid);

	/* Do the real setresgid */
	retval = func(rgid, egid, sgid);
	saved_errno = errno;

	lttng_ust_after_setresgid();

	errno = saved_errno;
	return retval;
}

#elif defined (__FreeBSD__)

pid_t rfork(int flags)
{
	sigset_t sigset;
	pid_t retval;
	int saved_errno;

	pid_t (*func)(int) = LAZY_INITIALIZE_OR_NOSYS(plibc_rfork);

	lttng_ust_before_fork(&sigset);
	/* Do the real rfork */
	retval = func(flags);
	saved_errno = errno;
	if (retval == 0) {
		/* child */
		lttng_ust_after_fork_child(&sigset);
	} else {
		lttng_ust_after_fork_parent(&sigset);
	}
	errno = saved_errno;
	return retval;
}

/*
 * On BSD, no need to override vfork, because it runs in the context of
 * the parent, with parent waiting until execve or exit is executed in
 * the child.
 */

#else
#warning "Unknown OS. You might want to ensure that fork/clone/vfork/fork handling is complete."
#endif
