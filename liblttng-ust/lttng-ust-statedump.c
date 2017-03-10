/*
 * Copyright (C) 2013  Paul Woegerer <paul_woegerer@mentor.com>
 * Copyright (C) 2015  Antoine Busque <abusque@efficios.com>
 * Copyright (C) 2016  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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
#define _LGPL_SOURCE
#include <link.h>
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>

#include <lttng/ust-elf.h>
#include <helper.h>
#include "lttng-tracer-core.h"
#include "lttng-ust-statedump.h"
#include "jhash.h"
#include "getenv.h"

#define TRACEPOINT_DEFINE
#include "ust_lib.h"				/* Only define. */

#define TRACEPOINT_CREATE_PROBES
#define TP_SESSION_CHECK
#include "lttng-ust-statedump-provider.h"	/* Define and create probes. */

struct dl_iterate_data {
	int exec_found;
	bool first;
	bool cancel;
};

struct bin_info_data {
	void *base_addr_ptr;
	char resolved_path[PATH_MAX];
	char *dbg_file;
	uint8_t *build_id;
	uint64_t memsz;
	size_t build_id_len;
	int vdso;
	uint32_t crc;
	uint8_t is_pic;
	uint8_t has_build_id;
	uint8_t has_debug_link;
};

struct lttng_ust_dl_node {
	struct bin_info_data bin_data;
	struct cds_hlist_node node;
	bool traced;
	bool marked;
};

#define UST_DL_STATE_HASH_BITS	8
#define UST_DL_STATE_TABLE_SIZE	(1 << UST_DL_STATE_HASH_BITS)
struct cds_hlist_head dl_state_table[UST_DL_STATE_TABLE_SIZE];

typedef void (*tracepoint_cb)(struct lttng_session *session, void *priv);

static
struct lttng_ust_dl_node *alloc_dl_node(const struct bin_info_data *bin_data)
{
	struct lttng_ust_dl_node *e;

	e = zmalloc(sizeof(struct lttng_ust_dl_node));
	if (!e)
		return NULL;
	if (bin_data->dbg_file) {
		e->bin_data.dbg_file = strdup(bin_data->dbg_file);
		if (!e->bin_data.dbg_file)
			goto error;
	}
	if (bin_data->build_id) {
		e->bin_data.build_id = zmalloc(bin_data->build_id_len);
		if (!e->bin_data.build_id)
			goto error;
		memcpy(e->bin_data.build_id, bin_data->build_id,
				bin_data->build_id_len);
	}
	e->bin_data.base_addr_ptr = bin_data->base_addr_ptr;
	memcpy(e->bin_data.resolved_path, bin_data->resolved_path, PATH_MAX);
	e->bin_data.memsz = bin_data->memsz;
	e->bin_data.build_id_len = bin_data->build_id_len;
	e->bin_data.vdso = bin_data->vdso;
	e->bin_data.crc = bin_data->crc;
	e->bin_data.is_pic = bin_data->is_pic;
	e->bin_data.has_build_id = bin_data->has_build_id;
	e->bin_data.has_debug_link = bin_data->has_debug_link;
	return e;

error:
	free(e->bin_data.build_id);
	free(e->bin_data.dbg_file);
	free(e);
	return NULL;
}

static
void free_dl_node(struct lttng_ust_dl_node *e)
{
	free(e->bin_data.build_id);
	free(e->bin_data.dbg_file);
	free(e);
}

/* Return 0 if same, nonzero if not. */
static
int compare_bin_data(const struct bin_info_data *a,
		const struct bin_info_data *b)
{
	if (a->base_addr_ptr != b->base_addr_ptr)
		return -1;
	if (strcmp(a->resolved_path, b->resolved_path) != 0)
		return -1;
	if (a->dbg_file && !b->dbg_file)
		return -1;
	if (!a->dbg_file && b->dbg_file)
		return -1;
	if (a->dbg_file && strcmp(a->dbg_file, b->dbg_file) != 0)
		return -1;
	if (a->build_id && !b->build_id)
		return -1;
	if (!a->build_id && b->build_id)
		return -1;
	if (a->build_id_len != b->build_id_len)
		return -1;
	if (a->build_id &&
			memcmp(a->build_id, b->build_id, a->build_id_len) != 0)
		return -1;
	if (a->memsz != b->memsz)
		return -1;
	if (a->vdso != b->vdso)
		return -1;
	if (a->crc != b->crc)
		return -1;
	if (a->is_pic != b->is_pic)
		return -1;
	if (a->has_build_id != b->has_build_id)
		return -1;
	if (a->has_debug_link != b->has_debug_link)
		return -1;
	return 0;
}

static
struct lttng_ust_dl_node *find_or_create_dl_node(struct bin_info_data *bin_data)
{
	struct cds_hlist_head *head;
	struct lttng_ust_dl_node *e;
	unsigned int hash;
	bool found = false;

	hash = jhash(&bin_data->base_addr_ptr,
		sizeof(bin_data->base_addr_ptr), 0);
	head = &dl_state_table[hash & (UST_DL_STATE_TABLE_SIZE - 1)];
	cds_hlist_for_each_entry_2(e, head, node) {
		if (compare_bin_data(&e->bin_data, bin_data) != 0)
			continue;
		found = true;
		break;
	}
	if (!found) {
		/* Create */
		e = alloc_dl_node(bin_data);
		if (!e)
			return NULL;
		cds_hlist_add_head(&e->node, head);
	}
	return e;
}

static
void remove_dl_node(struct lttng_ust_dl_node *e)
{
	cds_hlist_del(&e->node);
}

/*
 * Trace statedump event into all sessions owned by the caller thread
 * for which statedump is pending.
 */
static
void trace_statedump_event(tracepoint_cb tp_cb, void *owner, void *priv)
{
	struct cds_list_head *sessionsp;
	struct lttng_session *session;

	sessionsp = _lttng_get_sessions();
	cds_list_for_each_entry(session, sessionsp, node) {
		if (session->owner != owner)
			continue;
		if (!session->statedump_pending)
			continue;
		tp_cb(session, priv);
	}
}

static
void trace_bin_info_cb(struct lttng_session *session, void *priv)
{
	struct bin_info_data *bin_data = (struct bin_info_data *) priv;

	tracepoint(lttng_ust_statedump, bin_info,
		session, bin_data->base_addr_ptr,
		bin_data->resolved_path, bin_data->memsz,
		bin_data->is_pic, bin_data->has_build_id,
		bin_data->has_debug_link);
}

static
void trace_build_id_cb(struct lttng_session *session, void *priv)
{
	struct bin_info_data *bin_data = (struct bin_info_data *) priv;

	tracepoint(lttng_ust_statedump, build_id,
		session, bin_data->base_addr_ptr,
		bin_data->build_id, bin_data->build_id_len);
}

static
void trace_debug_link_cb(struct lttng_session *session, void *priv)
{
	struct bin_info_data *bin_data = (struct bin_info_data *) priv;

	tracepoint(lttng_ust_statedump, debug_link,
		session, bin_data->base_addr_ptr,
		bin_data->dbg_file, bin_data->crc);
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
int get_elf_info(struct bin_info_data *bin_data)
{
	struct lttng_ust_elf *elf;
	int ret = 0, found;

	elf = lttng_ust_elf_create(bin_data->resolved_path);
	if (!elf) {
		ret = -1;
		goto end;
	}

	ret = lttng_ust_elf_get_memsz(elf, &bin_data->memsz);
	if (ret) {
		goto end;
	}

	found = 0;
	ret = lttng_ust_elf_get_build_id(elf, &bin_data->build_id,
					&bin_data->build_id_len,
					&found);
	if (ret) {
		goto end;
	}
	bin_data->has_build_id = !!found;
	found = 0;
	ret = lttng_ust_elf_get_debug_link(elf, &bin_data->dbg_file,
					&bin_data->crc,
					&found);
	if (ret) {
		goto end;
	}
	bin_data->has_debug_link = !!found;

	bin_data->is_pic = lttng_ust_elf_is_pic(elf);

end:
	lttng_ust_elf_destroy(elf);
	return ret;
}

static
void trace_baddr(struct bin_info_data *bin_data, void *owner)
{
	trace_statedump_event(trace_bin_info_cb, owner, bin_data);

	if (bin_data->has_build_id)
		trace_statedump_event(trace_build_id_cb, owner, bin_data);

	if (bin_data->has_debug_link)
		trace_statedump_event(trace_debug_link_cb, owner, bin_data);
}

static
int extract_baddr(struct bin_info_data *bin_data)
{
	int ret = 0;
	struct lttng_ust_dl_node *e;

	if (!bin_data->vdso) {
		ret = get_elf_info(bin_data);
		if (ret) {
			goto end;
		}
	} else {
		bin_data->memsz = 0;
		bin_data->has_build_id = 0;
		bin_data->has_debug_link = 0;
	}

	e = find_or_create_dl_node(bin_data);
	if (!e) {
		ret = -1;
		goto end;
	}
	e->marked = true;
end:
	free(bin_data->build_id);
	bin_data->build_id = NULL;
	free(bin_data->dbg_file);
	bin_data->dbg_file = NULL;
	return ret;
}

static
void trace_statedump_start(void *owner)
{
	trace_statedump_event(trace_start_cb, owner, NULL);
}

static
void trace_statedump_end(void *owner)
{
	trace_statedump_event(trace_end_cb, owner, NULL);
}

static
void iter_begin(struct dl_iterate_data *data)
{
	unsigned int i;

	/*
	 * UST lock nests within dynamic loader lock.
	 *
	 * Hold this lock across handling of the module listing to
	 * protect memory allocation at early process start, due to
	 * interactions with libc-wrapper lttng malloc instrumentation.
	 */
	if (ust_lock()) {
		data->cancel = true;
		return;
	}

	/* Ensure all entries are unmarked. */
	for (i = 0; i < UST_DL_STATE_TABLE_SIZE; i++) {
		struct cds_hlist_head *head;
		struct lttng_ust_dl_node *e;

		head = &dl_state_table[i];
		cds_hlist_for_each_entry_2(e, head, node)
			assert(!e->marked);
	}
}

static
void trace_lib_load(const struct bin_info_data *bin_data, void *ip)
{
	tracepoint(lttng_ust_lib, load,
		ip, bin_data->base_addr_ptr, bin_data->resolved_path,
		bin_data->memsz, bin_data->has_build_id,
		bin_data->has_debug_link);

	if (bin_data->has_build_id) {
		tracepoint(lttng_ust_lib, build_id,
			ip, bin_data->base_addr_ptr, bin_data->build_id,
			bin_data->build_id_len);
	}

	if (bin_data->has_debug_link) {
		tracepoint(lttng_ust_lib, debug_link,
			ip, bin_data->base_addr_ptr, bin_data->dbg_file,
			bin_data->crc);
	}
}

static
void trace_lib_unload(const struct bin_info_data *bin_data, void *ip)
{
	tracepoint(lttng_ust_lib, unload, ip, bin_data->base_addr_ptr);
}

static
void iter_end(struct dl_iterate_data *data, void *ip)
{
	unsigned int i;

	/*
	 * Iterate on hash table.
	 * For each marked, traced, do nothing.
	 * For each marked, not traced, trace lib open event. traced = true.
	 * For each unmarked, traced, trace lib close event. remove node.
	 * For each unmarked, not traced, remove node.
	 */
	for (i = 0; i < UST_DL_STATE_TABLE_SIZE; i++) {
		struct cds_hlist_head *head;
		struct lttng_ust_dl_node *e;

		head = &dl_state_table[i];
		cds_hlist_for_each_entry_2(e, head, node) {
			if (e->marked) {
				if (!e->traced) {
					trace_lib_load(&e->bin_data, ip);
					e->traced = true;
				}
				e->marked = false;
			} else {
				if (e->traced)
					trace_lib_unload(&e->bin_data, ip);
				remove_dl_node(e);
				free_dl_node(e);
			}
		}
	}
	ust_unlock();
}

static
int extract_bin_info_events(struct dl_phdr_info *info, size_t size, void *_data)
{
	int j, ret = 0;
	struct dl_iterate_data *data = _data;

	if (data->first) {
		iter_begin(data);
		data->first = false;
	}

	if (data->cancel)
		goto end;

	for (j = 0; j < info->dlpi_phnum; j++) {
		struct bin_info_data bin_data;

		if (info->dlpi_phdr[j].p_type != PT_LOAD)
			continue;

		memset(&bin_data, 0, sizeof(bin_data));

		/* Calculate virtual memory address of the loadable segment */
		bin_data.base_addr_ptr = (void *) info->dlpi_addr +
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
						    bin_data.resolved_path,
						    PATH_MAX - 1);
				if (path_len <= 0)
					break;

				bin_data.resolved_path[path_len] = '\0';
				bin_data.vdso = 0;
			} else {
				snprintf(bin_data.resolved_path,
					PATH_MAX - 1, "[vdso]");
				bin_data.vdso = 1;
			}
		} else {
			/*
			 * For regular dl_phdr_info entries check if
			 * the path to the binary really exists. If not,
			 * treat as vdso and use dlpi_name as 'path'.
			 */
			if (!realpath(info->dlpi_name,
					bin_data.resolved_path)) {
				snprintf(bin_data.resolved_path,
					PATH_MAX - 1, "[%s]",
					info->dlpi_name);
				bin_data.vdso = 1;
			} else {
				bin_data.vdso = 0;
			}
		}

		ret = extract_baddr(&bin_data);
		break;
	}
end:
	return ret;
}

static
void ust_dl_table_statedump(void *owner)
{
	unsigned int i;

	if (ust_lock())
		goto end;

	/* Statedump each traced table entry into session for owner. */
	for (i = 0; i < UST_DL_STATE_TABLE_SIZE; i++) {
		struct cds_hlist_head *head;
		struct lttng_ust_dl_node *e;

		head = &dl_state_table[i];
		cds_hlist_for_each_entry_2(e, head, node) {
			if (e->traced)
				trace_baddr(&e->bin_data, owner);
		}
	}

end:
	ust_unlock();
}

void lttng_ust_dl_update(void *ip)
{
	struct dl_iterate_data data;

	if (lttng_getenv("LTTNG_UST_WITHOUT_BADDR_STATEDUMP"))
		return;

	/*
	 * Fixup lttng-ust TLS when called from dlopen/dlclose
	 * instrumentation.
	 */
	lttng_ust_fixup_tls();

	data.exec_found = 0;
	data.first = true;
	data.cancel = false;
	/*
	 * Iterate through the list of currently loaded shared objects and
	 * generate tables entries for loadable segments using
	 * extract_bin_info_events.
	 * Removed libraries are detected by mark-and-sweep: marking is
	 * done in the iteration over libraries, and sweeping is
	 * performed by iter_end().
	 */
	dl_iterate_phdr(extract_bin_info_events, &data);
	if (data.first)
		iter_begin(&data);
	iter_end(&data, ip);
}

/*
 * Generate a statedump of base addresses of all shared objects loaded
 * by the traced application, as well as for the application's
 * executable itself.
 */
static
int do_baddr_statedump(void *owner)
{
	if (lttng_getenv("LTTNG_UST_WITHOUT_BADDR_STATEDUMP"))
		return 0;
	lttng_ust_dl_update(LTTNG_UST_CALLER_IP());
	ust_dl_table_statedump(owner);
	return 0;
}

/*
 * Generate a statedump of a given traced application. A statedump is
 * delimited by start and end events. For a given (process, session)
 * pair, begin/end events are serialized and will match. However, in a
 * session, statedumps from different processes may be
 * interleaved. The vpid context should be used to identify which
 * events belong to which process.
 *
 * Grab the ust_lock outside of the RCU read-side lock because we
 * perform synchronize_rcu with the ust_lock held, which can trigger
 * deadlocks otherwise.
 */
int do_lttng_ust_statedump(void *owner)
{
	ust_lock_nocheck();
	trace_statedump_start(owner);
	ust_unlock();

	do_baddr_statedump(owner);

	ust_lock_nocheck();
	trace_statedump_end(owner);
	ust_unlock();

	return 0;
}

void lttng_ust_statedump_init(void)
{
	__tracepoints__init();
	__tracepoints__ptrs_init();
	__lttng_events_init__lttng_ust_statedump();
	lttng_ust_dl_update(LTTNG_UST_CALLER_IP());
}

static
void ust_dl_state_destroy(void)
{
	unsigned int i;

	for (i = 0; i < UST_DL_STATE_TABLE_SIZE; i++) {
		struct cds_hlist_head *head;
		struct lttng_ust_dl_node *e, *tmp;

		head = &dl_state_table[i];
		cds_hlist_for_each_entry_safe_2(e, tmp, head, node)
			free_dl_node(e);
		CDS_INIT_HLIST_HEAD(head);
	}
}

void lttng_ust_statedump_destroy(void)
{
	__lttng_events_exit__lttng_ust_statedump();
	__tracepoints__ptrs_destroy();
	__tracepoints__destroy();
	ust_dl_state_destroy();
}
