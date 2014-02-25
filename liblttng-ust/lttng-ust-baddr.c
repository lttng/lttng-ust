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

#define _LGPL_SOURCE
#define _GNU_SOURCE
#include <link.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#include <usterr-signal-safe.h>
#include "lttng-tracer-core.h"
#include "lttng-ust-baddr.h"

#define TRACEPOINT_DEFINE
#define TRACEPOINT_CREATE_PROBES
#define TP_SESSION_CHECK
#include "ust_baddr_statedump.h"

struct extract_data {
	void *owner;
	void *exec_baddr;	/* executable base address */
};

/*
 * Trace baddr into all sessions for which statedump is pending owned by
 * the caller thread.
 */
static
int trace_baddr(void *base_addr_ptr,
	const char *resolved_path,
	int vdso,
	void *owner)
{
	struct cds_list_head *sessionsp;
	struct lttng_session *session;
	struct stat sostat;

	if (vdso || stat(resolved_path, &sostat)) {
		sostat.st_size = 0;
		sostat.st_mtime = -1;
	}
	/*
	 * UST lock nests within dynamic loader lock.
	 */
	if (ust_lock()) {
		/*
		 * Stop iteration on headers if need to exit.
		 */
		ust_unlock();
		return 1;
	}

	sessionsp = _lttng_get_sessions();
	cds_list_for_each_entry(session, sessionsp, node) {
		if (session->owner != owner)
			continue;
		if (!session->statedump_pending)
			continue;
		tracepoint(ust_baddr_statedump, soinfo,
				session, base_addr_ptr,
				resolved_path, sostat.st_size,
				sostat.st_mtime);
	}
	ust_unlock();
	return 0;
}

static
int extract_soinfo_events(struct dl_phdr_info *info, size_t size, void *_data)
{
	int j;
	struct extract_data *data = _data;
	void *owner = data->owner;

	for (j = 0; j < info->dlpi_phnum; j++) {
		char resolved_path[PATH_MAX];
		void *base_addr_ptr;
		int vdso = 0;

		if (info->dlpi_phdr[j].p_type != PT_LOAD)
			continue;

		/* Calculate virtual memory address of the loadable segment */
		base_addr_ptr = (void *) info->dlpi_addr
			+ info->dlpi_phdr[j].p_vaddr;

		if ((info->dlpi_name == NULL || info->dlpi_name[0] == 0)
				&& !data->exec_baddr) {
			/*
			 * Only the first phdr encountered is considered
			 * as the program executable. The following
			 * could be e.g. vdso. Don't mistakenly dump
			 * them as being the program executable.
			 */
			data->exec_baddr = base_addr_ptr;
			/*
			 * Deal with program executable outside of phdr
			 * iteration.
			 */
			break;
		}
		if (info->dlpi_name == NULL || info->dlpi_name[0] == 0) {
			/* Found vDSO. */
			snprintf(resolved_path, PATH_MAX - 1, "[vdso]");
			vdso = 1;
		} else {
			/*
			 * For regular dl_phdr_info entries we have to check if
			 * the path to the shared object really exists.
			 */
			if (!realpath(info->dlpi_name, resolved_path)) {
				/* Path unknown, put the 'path' into brackets */
				snprintf(resolved_path, PATH_MAX - 1, "[%s]",
					info->dlpi_name);
				vdso = 1;
			}
		}
		if (trace_baddr(base_addr_ptr, resolved_path, vdso, owner)) {
			return 1;
		}
		/*
		 * We are only interested in the base address (lowest virtual
		 * address associated with the memory image), skip the rest
		 */
		break;
	}
	return 0;
}

static
void dump_exec_baddr(struct extract_data *data)
{
	void *owner = data->owner;
	void *base_addr_ptr;
	char exe_path[PATH_MAX];
	ssize_t exe_len;

	base_addr_ptr = data->exec_baddr;
	if (!base_addr_ptr)
		return;
	/*
	 * We have to use /proc/self/exe to determine the executable full
	 * path.
	 */
	exe_len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
	if (exe_len <= 0)
		return;
	exe_path[exe_len] = '\0';
	trace_baddr(base_addr_ptr, exe_path, 0, owner);
}

int lttng_ust_baddr_statedump(void *owner)
{
	struct extract_data data;

	if (getenv("LTTNG_UST_WITHOUT_BADDR_STATEDUMP"))
		return 0;

	data.owner = owner;
	data.exec_baddr = NULL;
	/*
	 * Iterate through the list of currently loaded shared objects and
	 * generate events for loadable segments using
	 * extract_soinfo_events.
	 */
	dl_iterate_phdr(extract_soinfo_events, &data);
	/*
	 * We cannot call dladdr() from within phdr iteration, without
	 * causing constructor vs dynamic loader vs multithread internal
	 * deadlocks, so dump the executable outside of the phdr
	 * iteration.
	 */
	dump_exec_baddr(&data);
	return 0;
}

void lttng_ust_baddr_statedump_init(void)
{
	__tracepoints__init();
	__tracepoints__ptrs_init();
	__lttng_events_init__ust_baddr_statedump();
}

void lttng_ust_baddr_statedump_destroy(void)
{
	__lttng_events_exit__ust_baddr_statedump();
	__tracepoints__ptrs_destroy();
	__tracepoints__destroy();
}
