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

#define _GNU_SOURCE
#include <inttypes.h>
#include <dlfcn.h>
#include <link.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <sched.h>
#include <stdarg.h>
#include "usterr.h"

#include <lttng/ust-compiler.h>
#include <lttng/ust.h>

static void *(*__lttng_ust_plibc_dlopen)(const char *filename, int flag);
static int (*__lttng_ust_plibc_dlclose)(void *handle);
static void *__lttng_ust_baddr_handle;

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
void *lttng_ust_baddr_handle(void)
{
	if (!__lttng_ust_baddr_handle) {
		__lttng_ust_baddr_handle = _lttng_ust_dl_libc_dlopen(
			"liblttng-ust-baddr.so.0", RTLD_NOW | RTLD_GLOBAL);
		if (__lttng_ust_baddr_handle == NULL)
			fprintf(stderr, "%s\n", dlerror());
	}
	return __lttng_ust_baddr_handle;
}

static
int lttng_ust_baddr_push(void *so_base, const char *so_name)
{
	static int
	(*lttng_ust_baddr_push_fn)(void *so_base, const char *so_name);
	if (!lttng_ust_baddr_push_fn) {
		void *baddr_handle = lttng_ust_baddr_handle();
		if (baddr_handle) {
			lttng_ust_baddr_push_fn = dlsym(baddr_handle,
				"lttng_ust_push_baddr");
			if (lttng_ust_baddr_push_fn == NULL)
				fprintf(stderr, "%s\n", dlerror());
		}
		if (!lttng_ust_baddr_push_fn)
			return -1;
	}
	return lttng_ust_baddr_push_fn(so_base, so_name);
}

static
int lttng_ust_baddr_pop(void *so_base)
{
	static int
	(*lttng_ust_baddr_pop_fn)(void *so_base);
	if (!lttng_ust_baddr_pop_fn) {
		void *baddr_handle = lttng_ust_baddr_handle();
		if (baddr_handle) {
			lttng_ust_baddr_pop_fn = dlsym(baddr_handle,
				"lttng_ust_pop_baddr");
			if (lttng_ust_baddr_pop_fn == NULL)
				fprintf(stderr, "%s\n", dlerror());
		}
		if (!lttng_ust_baddr_pop_fn)
			return -1;
	}
	return lttng_ust_baddr_pop_fn(so_base);
}

void *dlopen(const char *filename, int flag)
{
	void *handle = _lttng_ust_dl_libc_dlopen(filename, flag);
	if (handle) {
		struct link_map *p = NULL;
		if (dlinfo(handle, RTLD_DI_LINKMAP, &p) != -1 && p != NULL
				&& p->l_addr != 0)
			lttng_ust_baddr_push((void *) p->l_addr, p->l_name);
	}
	return handle;
}

int dlclose(void *handle)
{
	if (handle) {
		struct link_map *p = NULL;
		if (dlinfo(handle, RTLD_DI_LINKMAP, &p) != -1 && p != NULL
				&& p->l_addr != 0)
			lttng_ust_baddr_pop((void *) p->l_addr);
	}
	return _lttng_ust_dl_libc_dlclose(handle);
}

static void __attribute__((destructor))
lttng_ust_baddr_handle_fini(void);
static void
lttng_ust_baddr_handle_fini(void)
{
	if (__lttng_ust_baddr_handle) {
		int ret = _lttng_ust_dl_libc_dlclose(__lttng_ust_baddr_handle);
		if (ret)
			fprintf(stderr, "%s\n", dlerror());
	}
}
