/*
 * Copyright (C) 2013  Paul Woegerer <paul.woegerer@mentor.com>
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

#define _LGPL_SOURCE
#define _GNU_SOURCE
#include <lttng/ust-dlfcn.h>
#include <inttypes.h>
#include <link.h>
#include <unistd.h>
#include <stdio.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <sched.h>
#include <stdarg.h>
#include "usterr.h"

#include <lttng/ust-compiler.h>
#include <lttng/ust.h>

#define TRACEPOINT_DEFINE
#include "ust_baddr.h"

static void *(*__lttng_ust_plibc_dlopen)(const char *filename, int flag);
static int (*__lttng_ust_plibc_dlclose)(void *handle);

static
void *_lttng_ust_dl_libc_dlopen(const char *filename, int flag)
{
	if (!__lttng_ust_plibc_dlopen) {
		__lttng_ust_plibc_dlopen = dlsym(RTLD_NEXT, "dlopen");
		if (__lttng_ust_plibc_dlopen == NULL) {
			fprintf(stderr, "%s\n", dlerror());
			return NULL;
		}
	}
	return __lttng_ust_plibc_dlopen(filename, flag);
}

static
int _lttng_ust_dl_libc_dlclose(void *handle)
{
	if (!__lttng_ust_plibc_dlclose) {
		__lttng_ust_plibc_dlclose = dlsym(RTLD_NEXT, "dlclose");
		if (__lttng_ust_plibc_dlclose == NULL) {
			fprintf(stderr, "%s\n", dlerror());
			return -1;
		}
	}
	return __lttng_ust_plibc_dlclose(handle);
}

static
void lttng_ust_baddr_push(void *so_base, const char *so_name)
{
	char resolved_path[PATH_MAX];
	struct stat sostat;

	if (!realpath(so_name, resolved_path)) {
		ERR("could not resolve path '%s'", so_name);
		return;
	}

	if (stat(resolved_path, &sostat)) {
		ERR("could not access file status for %s", resolved_path);
		return;
	}

	tracepoint(ust_baddr, push,
		so_base, resolved_path, sostat.st_size, sostat.st_mtime);
	return;
}

void *dlopen(const char *filename, int flag)
{
	void *handle = _lttng_ust_dl_libc_dlopen(filename, flag);
	if (__tracepoint_ptrs_registered && handle) {
		struct link_map *p = NULL;
		if (dlinfo(handle, RTLD_DI_LINKMAP, &p) != -1 && p != NULL
				&& p->l_addr != 0)
			lttng_ust_baddr_push((void *) p->l_addr, p->l_name);
	}
	return handle;
}

int dlclose(void *handle)
{
	if (__tracepoint_ptrs_registered && handle) {
		struct link_map *p = NULL;
		if (dlinfo(handle, RTLD_DI_LINKMAP, &p) != -1 && p != NULL
				&& p->l_addr != 0)
			tracepoint(ust_baddr, pop, (void *) p->l_addr);
	}
	return _lttng_ust_dl_libc_dlclose(handle);
}
