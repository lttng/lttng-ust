/*
 * Copyright (C) 2013  Paul Woegerer <paul_woegerer@mentor.com>
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
#include <link.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "usterr.h"

#define TRACEPOINT_DEFINE
#include "ust_baddr.h"
#include "ust_baddr_statedump.h"

int
lttng_ust_push_baddr(void *so_base, const char *so_name)
{
	char resolved_path[PATH_MAX];
	struct stat sostat;

	if (!realpath(so_name, resolved_path)) {
		ERR("could not resolve path '%s'", so_name);
		return 0;
	}

	if (stat(resolved_path, &sostat)) {
		ERR("could not access file status for %s", resolved_path);
		return 0;
	}

	tracepoint(ust_baddr, push,
		so_base, resolved_path, sostat.st_size, sostat.st_mtime);
	return 0;
}

int
lttng_ust_pop_baddr(void *so_base)
{
	tracepoint(ust_baddr, pop, so_base);
	return 0;
}

static int
extract_soinfo_events(struct dl_phdr_info *info, size_t size, void *data)
{
	int j;
	int num_loadable_segment = 0;

	for (j = 0; j < info->dlpi_phnum; j++) {
		char resolved_path[PATH_MAX];
		struct stat sostat;
		void *base_addr_ptr;

		if (info->dlpi_phdr[j].p_type != PT_LOAD)
			continue;

		/* Calculate virtual memory address of the loadable segment */
		base_addr_ptr = (void *) info->dlpi_addr
			+ info->dlpi_phdr[j].p_vaddr;

		num_loadable_segment += 1;
		if ((info->dlpi_name == NULL || info->dlpi_name[0] == 0)
				&& num_loadable_segment == 1) {
			/*
			 * If the iterated element is the executable itself we
			 * have to use Dl_info to determine its full path
			 */
			Dl_info dl_info = { 0 };
			if (!dladdr(base_addr_ptr, &dl_info))
				return 0;
			if (!realpath(dl_info.dli_fname, resolved_path))
				return 0;
		} else {
			/*
			 * For regular dl_phdr_info entries we have to check if
			 * the path to the shared object really exists
			 */
			if (!realpath(info->dlpi_name, resolved_path)) {
				/* Found vDSO, put the 'path' into brackets */
				snprintf(resolved_path, PATH_MAX - 1, "[%s]",
						info->dlpi_name);
			}
		}

		if (stat(resolved_path, &sostat)) {
			sostat.st_size = 0;
			sostat.st_mtime = -1;
		}

		tracepoint(ust_baddr_statedump, soinfo,
				(struct lttng_session *) data, base_addr_ptr,
				resolved_path, sostat.st_size, sostat.st_mtime);

		/*
		 * We are only interested in the base address (lowest virtual
		 * address associated with the memory image), skip the rest
		 */
		break;
	}
	return 0;
}

int
lttng_ust_baddr_statedump(struct lttng_session *session)
{
	/*
	 * Iterate through the list of currently loaded shared objects and
	 * generate events for loadable segments using extract_soinfo_events
	 */
	dl_iterate_phdr(extract_soinfo_events, session);
	return 0;
}
