/*
 * Copyright (C) 2008 Mathieu Desnoyers
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

#include <errno.h>
#include <ust/tracepoint.h>
#include <ust/core.h>
#include <ust/kcompat/kcompat.h>
#include "usterr_signal_safe.h"

#define _LGPL_SOURCE
#include <urcu-bp.h>
#include <urcu/hlist.h>

//extern struct tracepoint __start___tracepoints[] __attribute__((visibility("hidden")));
//extern struct tracepoint __stop___tracepoints[] __attribute__((visibility("hidden")));

/* Set to 1 to enable tracepoint debug output */
static const int tracepoint_debug;

/* libraries that contain tracepoints (struct tracepoint_lib) */
static CDS_LIST_HEAD(libs);

/*
 * tracepoints_mutex nests inside module_mutex. Tracepoints mutex protects the
 * builtin and module tracepoints and the hash table.
 */
static DEFINE_MUTEX(tracepoints_mutex);

/*
 * Tracepoint hash table, containing the active tracepoints.
 * Protected by tracepoints_mutex.
 */
#define TRACEPOINT_HASH_BITS 6
#define TRACEPOINT_TABLE_SIZE (1 << TRACEPOINT_HASH_BITS)
static struct cds_hlist_head tracepoint_table[TRACEPOINT_TABLE_SIZE];

/*
 * Note about RCU :
 * It is used to to delay the free of multiple probes array until a quiescent
 * state is reached.
 * Tracepoint entries modifications are protected by the tracepoints_mutex.
 */
struct tracepoint_entry {
	struct cds_hlist_node hlist;
	struct tracepoint_probe *probes;
	int refcount;	/* Number of times armed. 0 if disarmed. */
	char name[0];
};

struct tp_probes {
	union {
//ust//		struct rcu_head rcu;
		struct cds_list_head list;
	} u;
	struct tracepoint_probe probes[0];
};

static inline void *allocate_probes(int count)
{
	struct tp_probes *p  = zmalloc(count * sizeof(struct tracepoint_probe)
			+ sizeof(struct tp_probes));
	return p == NULL ? NULL : p->probes;
}

//ust// static void rcu_free_old_probes(struct rcu_head *head)
//ust// {
//ust// 	kfree(container_of(head, struct tp_probes, u.rcu));
//ust// }

static inline void release_probes(void *old)
{
	if (old) {
		struct tp_probes *tp_probes = _ust_container_of(old,
			struct tp_probes, probes[0]);
//ust//		call_rcu_sched(&tp_probes->u.rcu, rcu_free_old_probes);
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
 * Must be called with tracepoints_mutex held.
 * Returns NULL if not present.
 */
static struct tracepoint_entry *get_tracepoint(const char *name)
{
	struct cds_hlist_head *head;
	struct cds_hlist_node *node;
	struct tracepoint_entry *e;
	u32 hash = jhash(name, strlen(name), 0);

	head = &tracepoint_table[hash & (TRACEPOINT_TABLE_SIZE - 1)];
	cds_hlist_for_each_entry(e, node, head, hlist) {
		if (!strcmp(name, e->name))
			return e;
	}
	return NULL;
}

/*
 * Add the tracepoint to the tracepoint hash table. Must be called with
 * tracepoints_mutex held.
 */
static struct tracepoint_entry *add_tracepoint(const char *name)
{
	struct cds_hlist_head *head;
	struct cds_hlist_node *node;
	struct tracepoint_entry *e;
	size_t name_len = strlen(name) + 1;
	u32 hash = jhash(name, name_len-1, 0);

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
 * mutex_lock held.
 */
static inline void remove_tracepoint(struct tracepoint_entry *e)
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
void tracepoint_update_probe_range(struct tracepoint * const *begin,
				   struct tracepoint * const *end)
{
	struct tracepoint * const *iter;
	struct tracepoint_entry *mark_entry;

	pthread_mutex_lock(&tracepoints_mutex);
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
	pthread_mutex_unlock(&tracepoints_mutex);
}

static void lib_update_tracepoints(void)
{
	struct tracepoint_lib *lib;

//ust//	pthread_mutex_lock(&module_mutex);
	cds_list_for_each_entry(lib, &libs, list)
		tracepoint_update_probe_range(lib->tracepoints_start,
				lib->tracepoints_start + lib->tracepoints_count);
//ust//	pthread_mutex_unlock(&module_mutex);
}

/*
 * Update probes, removing the faulty probes.
 */
static void tracepoint_update_probes(void)
{
	/* Core kernel tracepoints */
//ust//	tracepoint_update_probe_range(__start___tracepoints,
//ust//		__stop___tracepoints);
	/* tracepoints in modules. */
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
 * tracepoint_probe_register -  Connect a probe to a tracepoint
 * @name: tracepoint name
 * @probe: probe handler
 *
 * Returns 0 if ok, error value on error.
 * The probe address must at least be aligned on the architecture pointer size.
 */
int tracepoint_probe_register(const char *name, void *probe, void *data)
{
	void *old;

	pthread_mutex_lock(&tracepoints_mutex);
	old = tracepoint_add_probe(name, probe, data);
	pthread_mutex_unlock(&tracepoints_mutex);
	if (IS_ERR(old))
		return PTR_ERR(old);

	tracepoint_update_probes();		/* may update entry */
	release_probes(old);
	return 0;
}
//ust// EXPORT_SYMBOL_GPL(tracepoint_probe_register);

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
 * We do not need to call a synchronize_sched to make sure the probes have
 * finished running before doing a module unload, because the module unload
 * itself uses stop_machine(), which insures that every preempt disabled section
 * have finished.
 */
int tracepoint_probe_unregister(const char *name, void *probe, void *data)
{
	void *old;

	pthread_mutex_lock(&tracepoints_mutex);
	old = tracepoint_remove_probe(name, probe, data);
	pthread_mutex_unlock(&tracepoints_mutex);
	if (IS_ERR(old))
		return PTR_ERR(old);

	tracepoint_update_probes();		/* may update entry */
	release_probes(old);
	return 0;
}
//ust// EXPORT_SYMBOL_GPL(tracepoint_probe_unregister);

static CDS_LIST_HEAD(old_probes);
static int need_update;

static void tracepoint_add_old_probes(void *old)
{
	need_update = 1;
	if (old) {
		struct tp_probes *tp_probes = _ust_container_of(old,
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
 */
int tracepoint_probe_register_noupdate(const char *name, void *probe,
				       void *data)
{
	void *old;

	pthread_mutex_lock(&tracepoints_mutex);
	old = tracepoint_add_probe(name, probe, data);
	if (IS_ERR(old)) {
		pthread_mutex_unlock(&tracepoints_mutex);
		return PTR_ERR(old);
	}
	tracepoint_add_old_probes(old);
	pthread_mutex_unlock(&tracepoints_mutex);
	return 0;
}
//ust// EXPORT_SYMBOL_GPL(tracepoint_probe_register_noupdate);

/**
 * tracepoint_probe_unregister_noupdate -  remove a probe but not disconnect
 * @name: tracepoint name
 * @probe: probe function pointer
 *
 * caller must call tracepoint_probe_update_all()
 */
int tracepoint_probe_unregister_noupdate(const char *name, void *probe,
					 void *data)
{
	void *old;

	pthread_mutex_lock(&tracepoints_mutex);
	old = tracepoint_remove_probe(name, probe, data);
	if (IS_ERR(old)) {
		pthread_mutex_unlock(&tracepoints_mutex);
		return PTR_ERR(old);
	}
	tracepoint_add_old_probes(old);
	pthread_mutex_unlock(&tracepoints_mutex);
	return 0;
}
//ust// EXPORT_SYMBOL_GPL(tracepoint_probe_unregister_noupdate);

/**
 * tracepoint_probe_update_all -  update tracepoints
 */
void tracepoint_probe_update_all(void)
{
	CDS_LIST_HEAD(release_probes);
	struct tp_probes *pos, *next;

	pthread_mutex_lock(&tracepoints_mutex);
	if (!need_update) {
		pthread_mutex_unlock(&tracepoints_mutex);
		return;
	}
	if (!cds_list_empty(&old_probes))
		cds_list_replace_init(&old_probes, &release_probes);
	need_update = 0;
	pthread_mutex_unlock(&tracepoints_mutex);

	tracepoint_update_probes();
	cds_list_for_each_entry_safe(pos, next, &release_probes, u.list) {
		cds_list_del(&pos->u.list);
//ust//		call_rcu_sched(&pos->u.rcu, rcu_free_old_probes);
		synchronize_rcu();
		free(pos);
	}
}
//ust// EXPORT_SYMBOL_GPL(tracepoint_probe_update_all);

/*
 * Returns 0 if current not found.
 * Returns 1 if current found.
 */
int lib_get_iter_tracepoints(struct tracepoint_iter *iter)
{
	struct tracepoint_lib *iter_lib;
	int found = 0;

//ust//	pthread_mutex_lock(&module_mutex);
	cds_list_for_each_entry(iter_lib, &libs, list) {
		if (iter_lib < iter->lib)
			continue;
		else if (iter_lib > iter->lib)
			iter->tracepoint = NULL;
		found = tracepoint_get_iter_range(&iter->tracepoint,
			iter_lib->tracepoints_start,
			iter_lib->tracepoints_start + iter_lib->tracepoints_count);
		if (found) {
			iter->lib = iter_lib;
			break;
		}
	}
//ust//	pthread_mutex_unlock(&module_mutex);
	return found;
}

/**
 * tracepoint_get_iter_range - Get a next tracepoint iterator given a range.
 * @tracepoint: current tracepoints (in), next tracepoint (out)
 * @begin: beginning of the range
 * @end: end of the range
 *
 * Returns whether a next tracepoint has been found (1) or not (0).
 * Will return the first tracepoint in the range if the input tracepoint is
 * NULL.
 */
int tracepoint_get_iter_range(struct tracepoint * const **tracepoint,
	struct tracepoint * const *begin, struct tracepoint * const *end)
{
	if (!*tracepoint && begin != end)
		*tracepoint = begin;
	while (*tracepoint >= begin && *tracepoint < end) {
		if (!**tracepoint)
			(*tracepoint)++;	/* skip dummy */
		else
			return 1;
	}
	return 0;
}
//ust// EXPORT_SYMBOL_GPL(tracepoint_get_iter_range);

static void tracepoint_get_iter(struct tracepoint_iter *iter)
{
	int found = 0;

//ust//	/* Core kernel tracepoints */
//ust//	if (!iter->module) {
//ust//		found = tracepoint_get_iter_range(&iter->tracepoint,
//ust//				__start___tracepoints, __stop___tracepoints);
//ust//		if (found)
//ust//			goto end;
//ust//	}
	/* tracepoints in libs. */
	found = lib_get_iter_tracepoints(iter);
//ust// end:
	if (!found)
		tracepoint_iter_reset(iter);
}

void tracepoint_iter_start(struct tracepoint_iter *iter)
{
	tracepoint_get_iter(iter);
}
//ust// EXPORT_SYMBOL_GPL(tracepoint_iter_start);

void tracepoint_iter_next(struct tracepoint_iter *iter)
{
	iter->tracepoint++;
	/*
	 * iter->tracepoint may be invalid because we blindly incremented it.
	 * Make sure it is valid by marshalling on the tracepoints, getting the
	 * tracepoints from following modules if necessary.
	 */
	tracepoint_get_iter(iter);
}
//ust// EXPORT_SYMBOL_GPL(tracepoint_iter_next);

void tracepoint_iter_stop(struct tracepoint_iter *iter)
{
}
//ust// EXPORT_SYMBOL_GPL(tracepoint_iter_stop);

void tracepoint_iter_reset(struct tracepoint_iter *iter)
{
//ust//	iter->module = NULL;
	iter->tracepoint = NULL;
}
//ust// EXPORT_SYMBOL_GPL(tracepoint_iter_reset);

//ust// #ifdef CONFIG_MODULES

//ust// int tracepoint_module_notify(struct notifier_block *self,
//ust// 			     unsigned long val, void *data)
//ust// {
//ust// 	struct module *mod = data;
//ust// 
//ust// 	switch (val) {
//ust// 	case MODULE_STATE_COMING:
//ust// 		tracepoint_update_probe_range(mod->tracepoints,
//ust// 			mod->tracepoints + mod->num_tracepoints);
//ust// 		break;
//ust// 	case MODULE_STATE_GOING:
//ust// 		tracepoint_update_probe_range(mod->tracepoints,
//ust// 			mod->tracepoints + mod->num_tracepoints);
//ust// 		break;
//ust// 	}
//ust// 	return 0;
//ust// }

//ust// struct notifier_block tracepoint_module_nb = {
//ust// 	.notifier_call = tracepoint_module_notify,
//ust// 	.priority = 0,
//ust// };

//ust// static int init_tracepoints(void)
//ust// {
//ust// 	return register_module_notifier(&tracepoint_module_nb);
//ust// }
//ust// __initcall(init_tracepoints);

//ust// #endif /* CONFIG_MODULES */

static void (*new_tracepoint_cb)(struct tracepoint *) = NULL;

void tracepoint_set_new_tracepoint_cb(void (*cb)(struct tracepoint *))
{
	new_tracepoint_cb = cb;
}

static void new_tracepoints(struct tracepoint * const *start, struct tracepoint * const *end)
{
	if (new_tracepoint_cb) {
		struct tracepoint * const *t;

		for(t = start; t < end; t++) {
			if (*t)
				new_tracepoint_cb(*t);
		}
	}
}

int tracepoint_register_lib(struct tracepoint * const *tracepoints_start, int tracepoints_count)
{
	struct tracepoint_lib *pl, *iter;

	pl = (struct tracepoint_lib *) zmalloc(sizeof(struct tracepoint_lib));

	pl->tracepoints_start = tracepoints_start;
	pl->tracepoints_count = tracepoints_count;

	/* FIXME: maybe protect this with its own mutex? */
	pthread_mutex_lock(&tracepoints_mutex);
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
	pthread_mutex_unlock(&tracepoints_mutex);

	new_tracepoints(tracepoints_start, tracepoints_start + tracepoints_count);

	/* FIXME: update just the loaded lib */
	lib_update_tracepoints();

	/* tracepoints_count - 1: skip dummy */
	DBG("just registered a tracepoints section from %p and having %d tracepoints (minus dummy tracepoints)", tracepoints_start, tracepoints_count);

	return 0;
}

int tracepoint_unregister_lib(struct tracepoint * const *tracepoints_start)
{
	struct tracepoint_lib *lib;

	pthread_mutex_lock(&tracepoints_mutex);

	cds_list_for_each_entry(lib, &libs, list) {
		if (lib->tracepoints_start == tracepoints_start) {
			struct tracepoint_lib *lib2free = lib;
			cds_list_del(&lib->list);
			free(lib2free);
			break;
		}
	}

	pthread_mutex_unlock(&tracepoints_mutex);

	return 0;
}
