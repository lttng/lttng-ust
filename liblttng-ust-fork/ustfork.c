/*
 * Copyright (C) 2009  Pierre-Marc Fournier
 * Copyright (C) 2011-2012  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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
#include <lttng/ust-dlfcn.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <sched.h>
#include <stdarg.h>
#include <errno.h>

#include <lttng/ust.h>

pid_t fork(void)
{
	static pid_t (*plibc_func)(void) = NULL;
	sigset_t sigset;
	pid_t retval;

	if (plibc_func == NULL) {
		plibc_func = dlsym(RTLD_NEXT, "fork");
		if (plibc_func == NULL) {
			fprintf(stderr, "libustfork: unable to find \"fork\" symbol\n");
			errno = ENOSYS;
			return -1;
		}
	}

	ust_before_fork(&sigset);
	/* Do the real fork */
	retval = plibc_func();
	if (retval == 0) {
		/* child */
		ust_after_fork_child(&sigset);
	} else {
		ust_after_fork_parent(&sigset);
	}
	return retval;
}

int daemon(int nochdir, int noclose)
{
	static int (*plibc_func)(int nochdir, int noclose) = NULL;
	sigset_t sigset;
	int retval;

	if (plibc_func == NULL) {
		plibc_func = dlsym(RTLD_NEXT, "daemon");
		if (plibc_func == NULL) {
			fprintf(stderr, "libustfork: unable to find \"daemon\" symbol\n");
			errno = ENOSYS;
			return -1;
		}
	}

	ust_before_fork(&sigset);
	/* Do the real daemon call */
	retval = plibc_func(nochdir, noclose);
	if (retval == 0) {
		/* child, parent called _exit() directly */
		ust_after_fork_child(&sigset);
	} else {
		/* on error in the parent */
		ust_after_fork_parent(&sigset);
	}
	return retval;
}

#ifdef __linux__

struct user_desc;

struct ustfork_clone_info {
	int (*fn)(void *);
	void *arg;
	sigset_t sigset;
};

static int clone_fn(void *arg)
{
	struct ustfork_clone_info *info = (struct ustfork_clone_info *) arg;

	/* clone is now done and we are in child */
	ust_after_fork_child(&info->sigset);
	return info->fn(info->arg);
}

int clone(int (*fn)(void *), void *child_stack, int flags, void *arg, ...)
{
	static int (*plibc_func)(int (*fn)(void *), void *child_stack,
			int flags, void *arg, pid_t *ptid,
			struct user_desc *tls, pid_t *ctid) = NULL;
	/* var args */
	pid_t *ptid;
	struct user_desc *tls;
	pid_t *ctid;
	/* end of var args */
	va_list ap;
	int retval;

	va_start(ap, arg);
	ptid = va_arg(ap, pid_t *);
	tls = va_arg(ap, struct user_desc *);
	ctid = va_arg(ap, pid_t *);
	va_end(ap);

	if (plibc_func == NULL) {
		plibc_func = dlsym(RTLD_NEXT, "clone");
		if (plibc_func == NULL) {
			fprintf(stderr, "libustfork: unable to find \"clone\" symbol.\n");
			errno = ENOSYS;
			return -1;
		}
	}

	if (flags & CLONE_VM) {
		/*
		 * Creating a thread, no need to intervene, just pass on
		 * the arguments.
		 */
		retval = plibc_func(fn, child_stack, flags, arg, ptid,
				tls, ctid);
	} else {
		/* Creating a real process, we need to intervene. */
		struct ustfork_clone_info info = { .fn = fn, .arg = arg };

		ust_before_fork(&info.sigset);
		retval = plibc_func(clone_fn, child_stack, flags, &info,
				ptid, tls, ctid);
		/* The child doesn't get here. */
		ust_after_fork_parent(&info.sigset);
	}
	return retval;
}

#elif defined (__FreeBSD__)

pid_t rfork(int flags)
{
	static pid_t (*plibc_func)(void) = NULL;
	sigset_t sigset;
	pid_t retval;

	if (plibc_func == NULL) {
		plibc_func = dlsym(RTLD_NEXT, "rfork");
		if (plibc_func == NULL) {
			fprintf(stderr, "libustfork: unable to find \"rfork\" symbol\n");
			errno = ENOSYS;
			return -1;
		}
	}

	ust_before_fork(&sigset);
	/* Do the real rfork */
	retval = plibc_func();
	if (retval == 0) {
		/* child */
		ust_after_fork_child(&sigset);
	} else {
		ust_after_fork_parent(&sigset);
	}
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
