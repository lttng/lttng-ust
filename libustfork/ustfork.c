/* Copyright (C) 2009  Pierre-Marc Fournier
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
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
#include <dlfcn.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <sched.h>
#include <stdarg.h>
#include <ust/tracectl.h>
#include "usterr.h"

struct user_desc;

pid_t fork(void)
{
	static pid_t (*plibc_func)(void) = NULL;
	ust_fork_info_t fork_info;

	pid_t retval;

	if(plibc_func == NULL) {
		plibc_func = dlsym(RTLD_NEXT, "fork");
		if(plibc_func == NULL) {
			fprintf(stderr, "libcwrap: unable to find fork\n");
			return -1;
		}
	}

	ust_before_fork(&fork_info);

	/* Do the real fork */
	retval = plibc_func();

	if(retval == 0) {
		/* child */
		ust_after_fork_child(&fork_info);
	}
	else {
		ust_after_fork_parent(&fork_info);
	}

	return retval;
}

int execve(const char *filename, char *const argv[], char *const envp[])
{
	static int (*plibc_func)(const char *filename, char *const argv[], char *const envp[]) = NULL;

	pid_t retval;

	if(plibc_func == NULL) {
		plibc_func = dlsym(RTLD_NEXT, "execve");
		if(plibc_func == NULL) {
			fprintf(stderr, "libinterfork: unable to find execve\n");
			return -1;
		}
	}

	ust_potential_exec();

	retval = plibc_func(filename, argv, envp);

	return retval;
}

struct interfork_clone_info {
	int (*fn)(void *);
	void *arg;
	ust_fork_info_t fork_info;
};

static int clone_fn(void *arg)
{
	struct interfork_clone_info *info = (struct interfork_clone_info *)arg;

	/* clone is now done and we are in child */
	ust_after_fork_child(&info->fork_info);

	return info->fn(info->arg);
}

int clone(int (*fn)(void *), void *child_stack, int flags, void *arg, ...)
{
	static int (*plibc_func)(int (*fn)(void *), void *child_stack, int flags, void *arg, pid_t *ptid, struct user_desc *tls, pid_t *ctid) = NULL;

	/* varargs */
	pid_t *ptid;
	struct user_desc *tls;
	pid_t *ctid;

	int retval;

	va_list ap;

	va_start(ap, arg);
	ptid = va_arg(ap, pid_t *);
	tls = va_arg(ap, struct user_desc *);
	ctid = va_arg(ap, pid_t *);
	va_end(ap);

	if(plibc_func == NULL) {
		plibc_func = dlsym(RTLD_NEXT, "clone");
		if(plibc_func == NULL) {
			fprintf(stderr, "libinterfork: unable to find clone\n");
			return -1;
		}
	}

	if(flags & CLONE_VM) {
		/* creating a thread, no need to intervene, just pass on the arguments */
		retval = plibc_func(fn, child_stack, flags, arg, ptid, tls, ctid);
	}
	else {
		/* creating a real process, we need to intervene */
		struct interfork_clone_info info = { fn: fn, arg: arg };

		ust_before_fork(&info.fork_info);

		retval = plibc_func(clone_fn, child_stack, flags, &info, ptid, tls, ctid);

		/* The child doesn't get here */
		ust_after_fork_parent(&info.fork_info);
	}

	return retval;
}
