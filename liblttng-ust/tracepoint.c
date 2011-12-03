/*
 * Copyright (C) 2008-2011 Mathieu Desnoyers
 * Copyright (C) 2009 Pierre-Marc Fournier
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 *
 * Ported to userspace by Pierre-Marc Fournier.
 */

#define _LGPL_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stddef.h>

#include <urcu/arch.h>
#include <urcu-bp.h>
#include <urcu/hlist.h>
#include <urcu/uatomic.h>
#include <urcu/compiler.h>

#include <lttng/tracepoint.h>

#include <usterr-signal-safe.h>
#include <helper.h>

#include "tracepoint-internal.h"
#include "ltt-tracer-core.h"
#include "jhash.h"
#include "error.h"

/* Set to 1 to enable tracepoint debug output */
static const int tracepoint_debug;
static int initialized;
static void (*new_tracepoint_cb)(struct tracepoint *);

/*
 * libraries that contain tracepoints (struct tracepoint_lib).
 * Protected by UST lock.
 */
static CDS_LIST_HEAD(libs);

/*
 * The UST lock protects the library tracepoints, the hash table, and
 * the library list.
 * All calls to the tracepoint API must be protected by the UST lock,
 * excepts calls to tracepoint_register_lib and
 * tracepoint_unregister_lib, which take the UST lock themselves.
 */

/*
 * Tracepoint hash table, containing the active tracepoints.
 * Protected by ust lock.
 */
#define TRACEPOINT_HASH_BITS 6
#define TRACEPOINT_TABLE_SIZE (1 << TRACEPOINT_HASH_BITS)
static struct cds_hlist_head tracepoint_table[TRACEPOINT_TABLE_SIZE];

static CDS_LIST_HEAD(old_probes);
static int need_update;

/*
 * Note about RCU :
 * It is used to to delay the free of multiple probes array until a quiescent
 * state is reached.
 * Tracepoint entries modifications are protected by the ust lock.
 */
struct tracepoint_entry {
	struct cds_hlist_node hlist;
	struct tracepoint_probe *probes;
	int refcount;	/* Number of times armed. 0 if disarmed. */
	char name[0];
};

struct tp_probes {
	union {
		struct cds_list_head list;
	} u;
	struct tracepoint_probe probes[0];
};

static void *allocate_probes(int count)
{
	struct tp_probes *p  = zmalloc(count * sizeof(struct tracepoint_probe)
			+ sizeof(struct tp_probes));
	return p == NULL ? NULL : p->probes;
}

static void release_probes(void *old)
{
	if (old) {
		struct tp_probes *tp_probes = caa_container_of(old,
			struct tp_probes, probes[0]);
		synchronize_rcu();
		free(tp_probes);
	}
}

static void debug_print_probes(struct tracepoint_entry *entry)
{
	int i;

	if (!tracepoint_debug || !entry->probes)
		return;

	for (i = 0; entry->probes[i].func; i++)
		DBG("Probe %d : %p", i, entry->probes[i].func);
}

static void *
tracepoint_entry_add_probe(struct tracepoint_entry *entry,
			   void *probe, void *data)
{
	int nr_probes = 0;
	struct tracepoint_probe *old, *new;

	WARN_ON(!probe);

	debug_print_probes(entry);
	old = entry->probes;
	if (old) {
		/* (N -> N+1), (N != 0, 1) probes */
		for (nr_probes = 0; old[nr_probes].func; nr_probes++)
			if (old[nr_probes].func == probe &&
			    old[nr_probes].data == data)
				return ERR_PTR(-EEXIST);
	}
	/* + 2 : one for new probe, one for NULL func */
	new = allocate_probes(nr_probes + 2);
	if (new == NULL)
		return ERR_PTR(-ENOMEM);
	if (old)
		memcpy(new, old, nr_probes * sizeof(struct tracepoint_probe));
	new[nr_probes].func = probe;
	new[nr_probes].data = data;
	new[nr_probes + 1].func = NULL;
	entry->refcount = nr_probes + 1;
	entry->probes = new;
	debug_print_probes(entry);
	return old;
}

static void *
tracepoint_entry_remove_probe(struct tracepoint_entry *entry, void *probe,
			      void *data)
{
	int nr_probes = 0, nr_del = 0, i;
	struct tracepoint_probe *old, *new;

	old = entry->probes;

	if (!old)
		return ERR_PTR(-ENOENT);

	debug_print_probes(entry);
	/* (N -> M), (N > 1, M >= 0) probes */
	for (nr_probes = 0; old[nr_probes].func; nr_probes++) {
		if (!probe ||
		     (old[nr_probes].func == probe &&
		     old[nr_probes].data == data))
			nr_del++;
	}

	if (nr_probes - nr_del == 0) {
		/* N -> 0, (N > 1) */
		entry->probes = NULL;
		entry->refcount = 0;
		debug_print_probes(entry);
		return old;
	} else {
		int j = 0;
		/* N -> M, (N > 1, M > 0) */
		/* + 1 for NULL */
		new = allocate_probes(nr_probes - nr_del + 1);
		if (new == NULL)
			return ERR_PTR(-ENOMEM);
		for (i = 0; old[i].func; i++)
			if (probe &&
			    (old[i].func != probe || old[i].data != data))
				new[j++] = old[i];
		new[nr_probes - nr_del].func = NULL;
		entry->refcount = nr_probes - nr_del;
		entry->probes = new;
	}
	debug_print_probes(entry);
	return old;
}

/*
 * Get tracepoint if the tracepoint is present in the tracepoint hash table.
 * Must be called with ust lock held.
 * Returns NULL if not present.
 */
static struct tracepoint_entry *get_tracepoint(const char *name)
{
	struct cds_hlist_head *head;
	struct cds_hlist_node *node;
	struct tracepoint_entry *e;
	uint32_t hash = jhash(name, strlen(name), 0);

	head = &tracepoint_table[hash & (TRACEPOINT_TABLE_SIZE - 1)];
	cds_hlist_for_each_entry(e, node, head, hlist) {
		if (!strcmp(name, e->name))
			return e;
	}
	return NULL;
}

/*
 * Add the tracepoint to the tracepoint hash table. Must be called with
 * ust lock held.
 */
static struct tracepoint_entry *add_tracepoint(const char *name)
{
	struct cds_hlist_head *head;
	struct cds_hlist_node *node;
	struct tracepoint_entry *e;
	size_t name_len = strlen(name) + 1;
	uint32_t hash = jhash(name, name_len-1, 0);

	head = &tracepoint_table[hash & (TRACEPOINT_TABLE_SIZE - 1)];
	cds_hlist_for_each_entry(e, node, head, hlist) {
		if (!strcmp(name, e->name)) {
			DBG("tracepoint %s busy", name);
			return ERR_PTR(-EEXIST);	/* Already there */
		}
	}
	/*
	 * Using zmalloc here to allocate a variable length element. Could
	 * cause some memory fragmentation if overused.
	 */
	e = zmalloc(sizeof(struct tracepoint_entry) + name_len);
	if (!e)
		return ERR_PTR(-ENOMEM);
	memcpy(&e->name[0], name, name_len);
	e->probes = NULL;
	e->refcount = 0;
	cds_hlist_add_head(&e->hlist, head);
	return e;
}

/*
 * Remove the tracepoint from the tracepoint hash table. Must be called with
 * ust_lock held.
 */
static void remove_tracepoint(struct tracepoint_entry *e)
{
	cds_hlist_del(&e->hlist);
	free(e);
}

/*
 * Sets the probe callback corresponding to one tracepoint.
 */
static void set_tracepoint(struct tracepoint_entry **entry,
	struct tracepoint *elem, int active)
{
	WARN_ON(strcmp((*entry)->name, elem->name) != 0);

	/*
	 * rcu_assign_pointer has a cmm_smp_wmb() which makes sure that the new
	 * probe callbacks array is consistent before setting a pointer to it.
	 * This array is referenced by __DO_TRACE from
	 * include/linux/tracepoints.h. A matching cmm_smp_read_barrier_depends()
	 * is used.
	 */
	rcu_assign_pointer(elem->probes, (*entry)->probes);
	elem->state = active;
}

/*
 * Disable a tracepoint and its probe callback.
 * Note: only waiting an RCU period after setting elem->call to the empty
 * function insures that the original callback is not used anymore. This insured
 * by preempt_disable around the call site.
 */
static void disable_tracepoint(struct tracepoint *elem)
{
	elem->state = 0;
	rcu_assign_pointer(elem->probes, NULL);
}

/**
 * tracepoint_update_probe_range - Update a probe range
 * @begin: beginning of the range
 * @end: end of the range
 *
 * Updates the probe callback corresponding to a range of tracepoints.
 */
static
void tracepoint_update_probe_range(struct tracepoint * const *begin,
				   struct tracepoint * const *end)
{
	struct tracepoint * const *iter;
	struct tracepoint_entry *mark_entry;

	for (iter = begin; iter < end; iter++) {
		if (!*iter)
			continue;	/* skip dummy */
		if (!(*iter)->name) {
			disable_tracepoint(*iter);
			continue;
		}
		mark_entry = get_tracepoint((*iter)->name);
		if (mark_entry) {
			set_tracepoint(&mark_entry, *iter,
					!!mark_entry->refcount);
		} else {
			disable_tracepoint(*iter);
		}
	}
}

static void lib_update_tracepoints(void)
{
	struct tracepoint_lib *lib;

	cds_list_for_each_entry(lib, &libs, list) {
		tracepoint_update_probe_range(lib->tracepoints_start,
				lib->tracepoints_start + lib->tracepoints_count);
	}
}

/*
 * Update probes, removing the faulty probes.
 */
static void tracepoint_update_probes(void)
{
	/* tracepoints registered from libraries and executable. */
	lib_update_tracepoints();
}

static struct tracepoint_probe *
tracepoint_add_probe(const char *name, void *probe, void *data)
{
	struct tracepoint_entry *entry;
	struct tracepoint_probe *old;

	entry = get_tracepoint(name);
	if (!entry) {
		entry = add_tracepoint(name);
		if (IS_ERR(entry))
			return (struct tracepoint_probe *)entry;
	}
	old = tracepoint_entry_add_probe(entry, probe, data);
	if (IS_ERR(old) && !entry->refcount)
		remove_tracepoint(entry);
	return old;
}

/**
 * __tracepoint_probe_register -  Connect a probe to a tracepoint
 * @name: tracepoint name
 * @probe: probe handler
 *
 * Returns 0 if ok, error value on error.
 * The probe address must at least be aligned on the architecture pointer size.
 * Called with the UST lock held.
 */
int __tracepoint_probe_register(const char *name, void *probe, void *data)
{
	void *old;

	old = tracepoint_add_probe(name, probe, data);
	if (IS_ERR(old))
		return PTR_ERR(old);

	tracepoint_update_probes();		/* may update entry */
	release_probes(old);
	return 0;
}

static void *tracepoint_remove_probe(const char *name, void *probe, void *data)
{
	struct tracepoint_entry *entry;
	void *old;

	entry = get_tracepoint(name);
	if (!entry)
		return ERR_PTR(-ENOENT);
	old = tracepoint_entry_remove_probe(entry, probe, data);
	if (IS_ERR(old))
		return old;
	if (!entry->refcount)
		remove_tracepoint(entry);
	return old;
}

/**
 * tracepoint_probe_unregister -  Disconnect a probe from a tracepoint
 * @name: tracepoint name
 * @probe: probe function pointer
 * @probe: probe data pointer
 *
 * Called with the UST lock held.
 */
int __tracepoint_probe_unregister(const char *name, void *probe, void *data)
{
	void *old;

	old = tracepoint_remove_probe(name, probe, data);
	if (IS_ERR(old))
		return PTR_ERR(old);

	tracepoint_update_probes();		/* may update entry */
	release_probes(old);
	return 0;
}

static void tracepoint_add_old_probes(void *old)
{
	need_update = 1;
	if (old) {
		struct tp_probes *tp_probes = caa_container_of(old,
			struct tp_probes, probes[0]);
		cds_list_add(&tp_probes->u.list, &old_probes);
	}
}

/**
 * tracepoint_probe_register_noupdate -  register a probe but not connect
 * @name: tracepoint name
 * @probe: probe handler
 *
 * caller must call tracepoint_probe_update_all()
 * Called with the UST lock held.
 */
int tracepoint_probe_register_noupdate(const char *name, void *probe,
				       void *data)
{
	void *old;

	old = tracepoint_add_probe(name, probe, data);
	if (IS_ERR(old)) {
		return PTR_ERR(old);
	}
	tracepoint_add_old_probes(old);
	return 0;
}

/**
 * tracepoint_probe_unregister_noupdate -  remove a probe but not disconnect
 * @name: tracepoint name
 * @probe: probe function pointer
 *
 * caller must call tracepoint_probe_update_all()
 * Called with the UST lock held.
 */
int tracepoint_probe_unregister_noupdate(const char *name, void *probe,
					 void *data)
{
	void *old;

	old = tracepoint_remove_probe(name, probe, data);
	if (IS_ERR(old)) {
		return PTR_ERR(old);
	}
	tracepoint_add_old_probes(old);
	return 0;
}

/**
 * tracepoint_probe_update_all -  update tracepoints
 * Called with the UST lock held.
 */
void tracepoint_probe_update_all(void)
{
	CDS_LIST_HEAD(release_probes);
	struct tp_probes *pos, *next;

	if (!need_update) {
		return;
	}
	if (!cds_list_empty(&old_probes))
		cds_list_replace_init(&old_probes, &release_probes);
	need_update = 0;

	tracepoint_update_probes();
	cds_list_for_each_entry_safe(pos, next, &release_probes, u.list) {
		cds_list_del(&pos->u.list);
		synchronize_rcu();
		free(pos);
	}
}

void tracepoint_set_new_tracepoint_cb(void (*cb)(struct tracepoint *))
{
	new_tracepoint_cb = cb;
}

static void new_tracepoints(struct tracepoint * const *start, struct tracepoint * const *end)
{
	if (new_tracepoint_cb) {
		struct tracepoint * const *t;

		for (t = start; t < end; t++) {
			if (*t)
				new_tracepoint_cb(*t);
		}
	}
}

int tracepoint_register_lib(struct tracepoint * const *tracepoints_start,
			    int tracepoints_count)
{
	struct tracepoint_lib *pl, *iter;

	init_tracepoint();

	pl = (struct tracepoint_lib *) zmalloc(sizeof(struct tracepoint_lib));

	pl->tracepoints_start = tracepoints_start;
	pl->tracepoints_count = tracepoints_count;

	ust_lock();
	/*
	 * We sort the libs by struct lib pointer address.
	 */
	cds_list_for_each_entry_reverse(iter, &libs, list) {
		BUG_ON(iter == pl);    /* Should never be in the list twice */
		if (iter < pl) {
			/* We belong to the location right after iter. */
			cds_list_add(&pl->list, &iter->list);
			goto lib_added;
		}
	}
	/* We should be added at the head of the list */
	cds_list_add(&pl->list, &libs);
lib_added:
	new_tracepoints(tracepoints_start, tracepoints_start + tracepoints_count);

	/* TODO: update just the loaded lib */
	lib_update_tracepoints();
	ust_unlock();

	DBG("just registered a tracepoints section from %p and having %d tracepoints",
		tracepoints_start, tracepoints_count);

	return 0;
}

int tracepoint_unregister_lib(struct tracepoint * const *tracepoints_start)
{
	struct tracepoint_lib *lib;

	ust_lock();
	cds_list_for_each_entry(lib, &libs, list) {
		if (lib->tracepoints_start == tracepoints_start) {
			struct tracepoint_lib *lib2free = lib;
			cds_list_del(&lib->list);
			free(lib2free);
			break;
		}
	}
	ust_unlock();

	return 0;
}

void init_tracepoint(void)
{
	if (uatomic_xchg(&initialized, 1) == 1)
		return;
	init_usterr();
}

void exit_tracepoint(void)
{
	initialized = 0;
}
