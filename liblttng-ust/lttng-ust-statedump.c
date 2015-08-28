/*
 * Copyright (C) 2013  Paul Woegerer <paul_woegerer@mentor.com>
 * Copyright (C) 2015  Antoine Busque <abusque@efficios.com>
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
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <lttng/ust-elf.h>
#include "lttng-tracer-core.h"
#include "lttng-ust-statedump.h"

#define TRACEPOINT_DEFINE
#define TRACEPOINT_CREATE_PROBES
#define TP_SESSION_CHECK
#include "lttng-ust-statedump-provider.h"

struct dl_iterate_data {
	void *owner;
	int exec_found;
};

struct soinfo_data {
	void *owner;
	void *base_addr_ptr;
	const char *resolved_path;
	char *dbg_file;
	uint8_t *build_id;
	uint64_t memsz;
	size_t build_id_len;
	int vdso;
	uint32_t crc;
};

typedef void (*tracepoint_cb)(struct lttng_session *session, void *priv);

/*
 * Trace statedump event into all sessions owned by the caller thread
 * for which statedump is pending.
 */
static
int trace_statedump_event(tracepoint_cb tp_cb, void *owner, void *priv)
{
	struct cds_list_head *sessionsp;
	struct lttng_session *session;

	/*
	 * UST lock nests within dynamic loader lock.
	 */
	if (ust_lock()) {
		ust_unlock();
		return 1;
	}

	sessionsp = _lttng_get_sessions();
	cds_list_for_each_entry(session, sessionsp, node) {
		if (session->owner != owner)
			continue;
		if (!session->statedump_pending)
			continue;
		tp_cb(session, priv);
	}
	ust_unlock();
	return 0;
}

static
void trace_soinfo_cb(struct lttng_session *session, void *priv)
{
	struct soinfo_data *so_data = (struct soinfo_data *) priv;

	tracepoint(lttng_ust_statedump, soinfo,
		session, so_data->base_addr_ptr,
		so_data->resolved_path, so_data->memsz);
}

static
void trace_build_id_cb(struct lttng_session *session, void *priv)
{
	struct soinfo_data *so_data = (struct soinfo_data *) priv;

	tracepoint(lttng_ust_statedump, build_id,
		session, so_data->base_addr_ptr,
		so_data->build_id, so_data->build_id_len);
}

static
void trace_debug_link_cb(struct lttng_session *session, void *priv)
{
	struct soinfo_data *so_data = (struct soinfo_data *) priv;

	tracepoint(lttng_ust_statedump, debug_link,
		session, so_data->base_addr_ptr,
		so_data->dbg_file, so_data->crc);
}

static
void trace_start_cb(struct lttng_session *session, void *priv)
{
	tracepoint(lttng_ust_statedump, start, session);
}

static
void trace_end_cb(struct lttng_session *session, void *priv)
{
	tracepoint(lttng_ust_statedump, end, session);
}

static
int get_elf_info(struct soinfo_data *so_data, int *has_build_id,
		int *has_debug_link) {
	struct lttng_ust_elf *elf;
	int ret = 0;

	elf = lttng_ust_elf_create(so_data->resolved_path);
	if (!elf) {
		ret = -1;
		goto end;
	}

	ret = lttng_ust_elf_get_memsz(elf, &so_data->memsz);
	if (ret) {
		goto end;
	}

	ret = lttng_ust_elf_get_build_id(elf, &so_data->build_id,
					&so_data->build_id_len, has_build_id);
	if (ret) {
		goto end;
	}
	ret = lttng_ust_elf_get_debug_link(elf, &so_data->dbg_file,
					&so_data->crc, has_debug_link);
	if (ret) {
		goto end;
	}

end:
	lttng_ust_elf_destroy(elf);
	return ret;
}

static
int trace_baddr(struct soinfo_data *so_data)
{
	int ret = 0, has_build_id = 0, has_debug_link = 0;

	if (!so_data->vdso) {
		ret = get_elf_info(so_data, &has_build_id, &has_debug_link);
		if (ret) {
			goto end;
		}
	} else {
		so_data->memsz = 0;
	}

	ret = trace_statedump_event(trace_soinfo_cb, so_data->owner, so_data);
	if (ret) {
		goto end;
	}

	if (has_build_id) {
		ret = trace_statedump_event(
			trace_build_id_cb, so_data->owner, so_data);
		free(so_data->build_id);
		if (ret) {
			goto end;
		}
	}

	if (has_debug_link) {
		ret = trace_statedump_event(
			trace_debug_link_cb, so_data->owner, so_data);
		free(so_data->dbg_file);
		if (ret) {
			goto end;
		}
	}

end:
	return ret;
}

static
int trace_statedump_start(void *owner)
{
	return trace_statedump_event(trace_start_cb, owner, NULL);
}

static
int trace_statedump_end(void *owner)
{
	return trace_statedump_event(trace_end_cb, owner, NULL);
}

static
int extract_soinfo_events(struct dl_phdr_info *info, size_t size, void *_data)
{
	int j;
	struct dl_iterate_data *data = _data;

	for (j = 0; j < info->dlpi_phnum; j++) {
		struct soinfo_data so_data;
		char resolved_path[PATH_MAX];
		void *base_addr_ptr;

		if (info->dlpi_phdr[j].p_type != PT_LOAD)
			continue;

		/* Calculate virtual memory address of the loadable segment */
		base_addr_ptr = (void *) info->dlpi_addr +
			info->dlpi_phdr[j].p_vaddr;

		if ((info->dlpi_name == NULL || info->dlpi_name[0] == 0)) {
			/*
			 * Only the first phdr without a dlpi_name
			 * encountered is considered as the program
			 * executable. The rest are vdsos.
			 */
			if (!data->exec_found) {
				ssize_t path_len;
				data->exec_found = 1;

				/*
				 * Use /proc/self/exe to resolve the
				 * executable's full path.
				 */
				path_len = readlink("/proc/self/exe",
						    resolved_path,
						    PATH_MAX - 1);
				if (path_len <= 0)
					break;

				resolved_path[path_len] = '\0';
				so_data.vdso = 0;
			} else {
				snprintf(resolved_path, PATH_MAX - 1, "[vdso]");
				so_data.vdso = 1;
			}
		} else {
			/*
			 * For regular dl_phdr_info entries check if
			 * the path to the SO really exists. If not,
			 * treat as vdso and use dlpi_name as 'path'.
			 */
			if (!realpath(info->dlpi_name, resolved_path)) {
				snprintf(resolved_path, PATH_MAX - 1, "[%s]",
					info->dlpi_name);
				so_data.vdso = 1;
			} else {
				so_data.vdso = 0;
			}
		}

		so_data.owner = data->owner;
		so_data.base_addr_ptr = base_addr_ptr;
		so_data.resolved_path = resolved_path;
		return trace_baddr(&so_data);
	}

	return 0;
}

/*
 * Generate a statedump of base addresses of all shared objects loaded
 * by the traced application, as well as for the application's
 * executable itself.
 */
static
int do_baddr_statedump(void *owner)
{
	struct dl_iterate_data data;

	if (getenv("LTTNG_UST_WITHOUT_BADDR_STATEDUMP"))
		return 0;

	data.owner = owner;
	data.exec_found = 0;
	/*
	 * Iterate through the list of currently loaded shared objects and
	 * generate events for loadable segments using
	 * extract_soinfo_events.
	 */
	dl_iterate_phdr(extract_soinfo_events, &data);

	return 0;
}

/*
 * Generate a statedump of a given traced application. A statedump is
 * delimited by start and end events. For a given (process, session)
 * pair, begin/end events are serialized and will match. However, in a
 * session, statedumps from different processes may be
 * interleaved. The vpid context should be used to identify which
 * events belong to which process.
 */
int do_lttng_ust_statedump(void *owner)
{
	trace_statedump_start(owner);
	do_baddr_statedump(owner);
	trace_statedump_end(owner);

	return 0;
}

void lttng_ust_statedump_init(void)
{
	__tracepoints__init();
	__tracepoints__ptrs_init();
	__lttng_events_init__lttng_ust_statedump();
}

void lttng_ust_statedump_destroy(void)
{
	__lttng_events_exit__lttng_ust_statedump();
	__tracepoints__ptrs_destroy();
	__tracepoints__destroy();
}
