/*
 * Copyright (C) 2013  Paul Woegerer <paul.woegerer@mentor.com>
 * Copyright (C) 2015  Antoine Busque <abusque@efficios.com>
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

#include <lttng/ust-dlfcn.h>
#include <lttng/ust-elf.h>
#include <lttng/ust-events.h>
#include <helper.h>
#include "usterr-signal-safe.h"

/* Include link.h last else it conflicts with ust-dlfcn. */
#include <link.h>

#define TRACEPOINT_DEFINE
#include "ust_dl.h"

static void *(*__lttng_ust_plibc_dlopen)(const char *filename, int flags);
#ifdef HAVE_DLMOPEN
static void *(*__lttng_ust_plibc_dlmopen)(Lmid_t nsid, const char *filename,
		int flags);
#endif
static int (*__lttng_ust_plibc_dlclose)(void *handle);

static
void *_lttng_ust_dl_libc_dlopen(const char *filename, int flags)
{
	if (!__lttng_ust_plibc_dlopen) {
		__lttng_ust_plibc_dlopen = dlsym(RTLD_NEXT, "dlopen");
		if (!__lttng_ust_plibc_dlopen) {
			fprintf(stderr, "%s\n", dlerror());
			return NULL;
		}
	}
	return __lttng_ust_plibc_dlopen(filename, flags);
}

#ifdef HAVE_DLMOPEN
static
void *_lttng_ust_dl_libc_dlmopen(Lmid_t nsid, const char *filename,
		int flags)
{
	if (!__lttng_ust_plibc_dlmopen) {
		__lttng_ust_plibc_dlmopen = dlsym(RTLD_NEXT, "dlmopen");
		if (!__lttng_ust_plibc_dlmopen) {
			fprintf(stderr, "%s\n", dlerror());
			return NULL;
		}
	}
	return __lttng_ust_plibc_dlmopen(nsid, filename, flags);
}
#endif

static
int _lttng_ust_dl_libc_dlclose(void *handle)
{
	if (!__lttng_ust_plibc_dlclose) {
		__lttng_ust_plibc_dlclose = dlsym(RTLD_NEXT, "dlclose");
		if (!__lttng_ust_plibc_dlclose) {
			fprintf(stderr, "%s\n", dlerror());
			return -1;
		}
	}
	return __lttng_ust_plibc_dlclose(handle);
}

static
void lttng_ust_dl_dlopen(void *so_base, const char *so_name,
		int flags, void *ip)
{
	char resolved_path[PATH_MAX];
	struct lttng_ust_elf *elf;
	uint64_t memsz;
	uint8_t *build_id = NULL;
	size_t build_id_len;
	char *dbg_file = NULL;
	uint32_t crc;
	int has_build_id = 0, has_debug_link = 0;
	int ret;

	if (!realpath(so_name, resolved_path)) {
		ERR("could not resolve path '%s'", so_name);
		return;
	}

	elf = lttng_ust_elf_create(resolved_path);
	if (!elf) {
		ERR("could not acces file %s", resolved_path);
		return;
	}

	ret = lttng_ust_elf_get_memsz(elf, &memsz);
	if (ret) {
		goto end;
	}
	ret = lttng_ust_elf_get_build_id(
		elf, &build_id, &build_id_len, &has_build_id);
	if (ret) {
		goto end;
	}
	ret = lttng_ust_elf_get_debug_link(
		elf, &dbg_file, &crc, &has_debug_link);
	if (ret) {
		goto end;
	}

	tracepoint(lttng_ust_dl, dlopen,
		ip, so_base, resolved_path, flags, memsz,
		has_build_id, has_debug_link);

	if (has_build_id) {
		tracepoint(lttng_ust_dl, build_id,
			ip, so_base, build_id, build_id_len);
	}

	if (has_debug_link) {
		tracepoint(lttng_ust_dl, debug_link,
			ip, so_base, dbg_file, crc);
	}

end:
	free(dbg_file);
	free(build_id);
	lttng_ust_elf_destroy(elf);
	return;
}

#ifdef HAVE_DLMOPEN
static
void lttng_ust_dl_dlmopen(void *so_base, Lmid_t nsid, const char *so_name,
		int flags, void *ip)
{
	char resolved_path[PATH_MAX];
	struct lttng_ust_elf *elf;
	uint64_t memsz;
	uint8_t *build_id = NULL;
	size_t build_id_len;
	char *dbg_file = NULL;
	uint32_t crc;
	int has_build_id = 0, has_debug_link = 0;
	int ret;

	if (!realpath(so_name, resolved_path)) {
		ERR("could not resolve path '%s'", so_name);
		return;
	}

	elf = lttng_ust_elf_create(resolved_path);
	if (!elf) {
		ERR("could not acces file %s", resolved_path);
		return;
	}

	ret = lttng_ust_elf_get_memsz(elf, &memsz);
	if (ret) {
		goto end;
	}
	ret = lttng_ust_elf_get_build_id(
		elf, &build_id, &build_id_len, &has_build_id);
	if (ret) {
		goto end;
	}
	ret = lttng_ust_elf_get_debug_link(
		elf, &dbg_file, &crc, &has_debug_link);
	if (ret) {
		goto end;
	}

	tracepoint(lttng_ust_dl, dlmopen,
		ip, so_base, nsid, resolved_path, flags, memsz,
		has_build_id, has_debug_link);

	if (has_build_id) {
		tracepoint(lttng_ust_dl, build_id,
			ip, so_base, build_id, build_id_len);
	}

	if (has_debug_link) {
		tracepoint(lttng_ust_dl, debug_link,
			ip, so_base, dbg_file, crc);
	}

end:
	free(dbg_file);
	free(build_id);
	lttng_ust_elf_destroy(elf);
	return;
}
#endif

void *dlopen(const char *filename, int flags)
{
	void *handle;

	handle = _lttng_ust_dl_libc_dlopen(filename, flags);
	if (__tracepoint_ptrs_registered && handle) {
		struct link_map *p = NULL;
		int ret;

		ret = dlinfo(handle, RTLD_DI_LINKMAP, &p);
		if (ret != -1 && p != NULL && p->l_addr != 0) {
			lttng_ust_dl_dlopen((void *) p->l_addr,
				p->l_name, flags, LTTNG_UST_CALLER_IP());
		}
	}
	lttng_ust_dl_update(LTTNG_UST_CALLER_IP());
	return handle;
}

#ifdef HAVE_DLMOPEN
void *dlmopen(Lmid_t nsid, const char *filename, int flags)
{
	void *handle;

	handle = _lttng_ust_dl_libc_dlmopen(nsid, filename, flags);
	if (__tracepoint_ptrs_registered && handle) {
		struct link_map *p = NULL;
		int ret;

		ret = dlinfo(handle, RTLD_DI_LINKMAP, &p);
		if (ret != -1 && p != NULL && p->l_addr != 0) {
			lttng_ust_dl_dlmopen((void *) p->l_addr,
				nsid, p->l_name, flags,
				LTTNG_UST_CALLER_IP());
		}
	}
	lttng_ust_dl_update(LTTNG_UST_CALLER_IP());
	return handle;

}
#endif

int dlclose(void *handle)
{
	int ret;

	if (__tracepoint_ptrs_registered) {
		struct link_map *p = NULL;

		ret = dlinfo(handle, RTLD_DI_LINKMAP, &p);
		if (ret != -1 && p != NULL && p->l_addr != 0) {
			tracepoint(lttng_ust_dl, dlclose,
				LTTNG_UST_CALLER_IP(),
				(void *) p->l_addr);
		}
	}
	ret = _lttng_ust_dl_libc_dlclose(handle);
	lttng_ust_dl_update(LTTNG_UST_CALLER_IP());
	return ret;
}
