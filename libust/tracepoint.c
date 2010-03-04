/*
 * Copyright (C) 2008 Mathieu Desnoyers
 * Copyright (C) 2009 Pierre-Marc Fournier
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
 *
 * Ported to userspace by Pierre-Marc Fournier.
 */

//ust// #include <linux/module.h>
//ust// #include <linux/mutex.h>
//ust// #include <linux/types.h>
//ust// #include <linux/jhash.h>
//ust// #include <linux/list.h>
//ust// #include <linux/rcupdate.h>
//ust// #include <linux/tracepoint.h>
//ust// #include <linux/err.h>
//ust// #include <linux/slab.h>
//ust// #include <linux/immediate.h>

#include <errno.h>

#include <ust/kernelcompat.h>
#include <ust/tracepoint.h>
#include "usterr.h"
//#include "list.h"

#define _LGPL_SOURCE
#include <urcu-bp.h>

//extern struct tracepoint __start___tracepoints[] __attribute__((visibility("hidden")));
//extern struct tracepoint __stop___tracepoints[] __attribute__((visibility("hidden")));

/* Set to 1 to enable tracepoint debug output */
static const int tracepoint_debug;

/* libraries that contain tracepoints (struct tracepoint_lib) */
static LIST_HEAD(libs);

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
static struct hlist_head tracepoint_table[TRACEPOINT_TABLE_SIZE];

/*
 * Note about RCU :
 * It is used to to delay the free of multiple probes array until a quiescent
 * state is reached.
 * Tracepoint entries modifications are protected by the tracepoints_mutex.
 */
struct tracepoint_entry {
	struct hlist_node hlist;
	void **funcs;
	int refcount;	/* Number of times armed. 0 if disarmed. */
	char name[0];
};

struct tp_probes {
	union {
//ust//		struct rcu_head rcu;
		struct list_head list;
	} u;
	void *probes[0];
};

static inline void *allocate_probes(int count)
{
	struct tp_probes *p  = malloc(count * sizeof(void *)
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
		struct tp_probes *tp_probes = container_of(old,
			struct tp_probes, probes[0]);
//ust//		call_rcu_sched(&tp_probes->u.rcu, rcu_free_old_probes);
		synchronize_rcu();
		free(tp_probes);
	}
}

static void debug_print_probes(struct tracepoint_entry *entry)
{
	int i;

	if (!tracepoint_debug || !entry->funcs)
		return;

	for (i = 0; entry->funcs[i]; i++)
		DBG("Probe %d : %p", i, entry->funcs[i]);
}

static void *
tracepoint_entry_add_probe(struct tracepoint_entry *entry, void *probe)
{
	int nr_probes = 0;
	void **old, **new;

	WARN_ON(!probe);

	debug_print_probes(entry);
	old = entry->funcs;
	if (old) {
		/* (N -> N+1), (N != 0, 1) probes */
		for (nr_probes = 0; old[nr_probes]; nr_probes++)
			if (old[nr_probes] == probe)
				return ERR_PTR(-EEXIST);
	}
	/* + 2 : one for new probe, one for NULL func */
	new = allocate_probes(nr_probes + 2);
	if (new == NULL)
		return ERR_PTR(-ENOMEM);
	if (old)
		memcpy(new, old, nr_probes * sizeof(void *));
	new[nr_probes] = probe;
	new[nr_probes + 1] = NULL;
	entry->refcount = nr_probes + 1;
	entry->funcs = new;
	debug_print_probes(entry);
	return old;
}

static void *
tracepoint_entry_remove_probe(struct tracepoint_entry *entry, void *probe)
{
	int nr_probes = 0, nr_del = 0, i;
	void **old, **new;

	old = entry->funcs;

	if (!old)
		return ERR_PTR(-ENOENT);

	debug_print_probes(entry);
	/* (N -> M), (N > 1, M >= 0) probes */
	for (nr_probes = 0; old[nr_probes]; nr_probes++) {
		if ((!probe || old[nr_probes] == probe))
			nr_del++;
	}

	if (nr_probes - nr_del == 0) {
		/* N -> 0, (N > 1) */
		entry->funcs = NULL;
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
		for (i = 0; old[i]; i++)
			if ((probe && old[i] != probe))
				new[j++] = old[i];
		new[nr_probes - nr_del] = NULL;
		entry->refcount = nr_probes - nr_del;
		entry->funcs = new;
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
	struct hlist_head *head;
	struct hlist_node *node;
	struct tracepoint_entry *e;
	u32 hash = jhash(name, strlen(name), 0);

	head = &tracepoint_table[hash & (TRACEPOINT_TABLE_SIZE - 1)];
	hlist_for_each_entry(e, node, head, hlist) {
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
	struct hlist_head *head;
	struct hlist_node *node;
	struct tracepoint_entry *e;
	size_t name_len = strlen(name) + 1;
	u32 hash = jhash(name, name_len-1, 0);

	head = &tracepoint_table[hash & (TRACEPOINT_TABLE_SIZE - 1)];
	hlist_for_each_entry(e, node, head, hlist) {
		if (!strcmp(name, e->name)) {
			DBG("tracepoint %s busy", name);
			return ERR_PTR(-EEXIST);	/* Already there */
		}
	}
	/*
	 * Using kmalloc here to allocate a variable length element. Could
	 * cause some memory fragmentation if overused.
	 */
	e = malloc(sizeof(struct tracepoint_entry) + name_len);
	if (!e)
		return ERR_PTR(-ENOMEM);
	memcpy(&e->name[0], name, name_len);
	e->funcs = NULL;
	e->refcount = 0;
	hlist_add_head(&e->hlist, head);
	return e;
}

/*
 * Remove the tracepoint from the tracepoint hash table. Must be called with
 * mutex_lock held.
 */
static inline void remove_tracepoint(struct tracepoint_entry *e)
{
	hlist_del(&e->hlist);
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
	 * rcu_assign_pointer has a smp_wmb() which makes sure that the new
	 * probe callbacks array is consistent before setting a pointer to it.
	 * This array is referenced by __DO_TRACE from
	 * include/linux/tracepoints.h. A matching smp_read_barrier_depends()
	 * is used.
	 */
	rcu_assign_pointer(elem->funcs, (*entry)->funcs);
	elem->state__imv = active;
}

/*
 * Disable a tracepoint and its probe callback.
 * Note: only waiting an RCU period after setting elem->call to the empty
 * function insures that the original callback is not used anymore. This insured
 * by preempt_disable around the call site.
 */
static void disable_tracepoint(struct tracepoint *elem)
{
	elem->state__imv = 0;
	rcu_assign_pointer(elem->funcs, NULL);
}

/**
 * tracepoint_update_probe_range - Update a probe range
 * @begin: beginning of the range
 * @end: end of the range
 *
 * Updates the probe callback corresponding to a range of tracepoints.
 */
void tracepoint_update_probe_range(struct tracepoint *begin,
	struct tracepoint *end)
{
	struct tracepoint *iter;
	struct tracepoint_entry *mark_entry;

	mutex_lock(&tracepoints_mutex);
	for (iter = begin; iter < end; iter++) {
		mark_entry = get_tracepoint(iter->name);
		if (mark_entry) {
			set_tracepoint(&mark_entry, iter,
					!!mark_entry->refcount);
		} else {
			disable_tracepoint(iter);
		}
	}
	mutex_unlock(&tracepoints_mutex);
}

static void lib_update_tracepoints(void)
{
	struct tracepoint_lib *lib;

//ust//	mutex_lock(&module_mutex);
	list_for_each_entry(lib, &libs, list)
		tracepoint_update_probe_range(lib->tracepoints_start,
				lib->tracepoints_start + lib->tracepoints_count);
//ust//	mutex_unlock(&module_mutex);
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
	/* Update immediate values */
	core_imv_update();
//ust//	module_imv_update();
}

static void *tracepoint_add_probe(const char *name, void *probe)
{
	struct tracepoint_entry *entry;
	void *old;

	entry = get_tracepoint(name);
	if (!entry) {
		entry = add_tracepoint(name);
		if (IS_ERR(entry))
			return entry;
	}
	old = tracepoint_entry_add_probe(entry, probe);
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
int tracepoint_probe_register(const char *name, void *probe)
{
	void *old;

	mutex_lock(&tracepoints_mutex);
	old = tracepoint_add_probe(name, probe);
	mutex_unlock(&tracepoints_mutex);
	if (IS_ERR(old))
		return PTR_ERR(old);

	tracepoint_update_probes();		/* may update entry */
	release_probes(old);
	return 0;
}
//ust// EXPORT_SYMBOL_GPL(tracepoint_probe_register);

static void *tracepoint_remove_probe(const char *name, void *probe)
{
	struct tracepoint_entry *entry;
	void *old;

	entry = get_tracepoint(name);
	if (!entry)
		return ERR_PTR(-ENOENT);
	old = tracepoint_entry_remove_probe(entry, probe);
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
 *
 * We do not need to call a synchronize_sched to make sure the probes have
 * finished running before doing a module unload, because the module unload
 * itself uses stop_machine(), which insures that every preempt disabled section
 * have finished.
 */
int tracepoint_probe_unregister(const char *name, void *probe)
{
	void *old;

	mutex_lock(&tracepoints_mutex);
	old = tracepoint_remove_probe(name, probe);
	mutex_unlock(&tracepoints_mutex);
	if (IS_ERR(old))
		return PTR_ERR(old);

	tracepoint_update_probes();		/* may update entry */
	release_probes(old);
	return 0;
}
//ust// EXPORT_SYMBOL_GPL(tracepoint_probe_unregister);

static LIST_HEAD(old_probes);
static int need_update;

static void tracepoint_add_old_probes(void *old)
{
	need_update = 1;
	if (old) {
		struct tp_probes *tp_probes = container_of(old,
			struct tp_probes, probes[0]);
		list_add(&tp_probes->u.list, &old_probes);
	}
}

/**
 * tracepoint_probe_register_noupdate -  register a probe but not connect
 * @name: tracepoint name
 * @probe: probe handler
 *
 * caller must call tracepoint_probe_update_all()
 */
int tracepoint_probe_register_noupdate(const char *name, void *probe)
{
	void *old;

	mutex_lock(&tracepoints_mutex);
	old = tracepoint_add_probe(name, probe);
	if (IS_ERR(old)) {
		mutex_unlock(&tracepoints_mutex);
		return PTR_ERR(old);
	}
	tracepoint_add_old_probes(old);
	mutex_unlock(&tracepoints_mutex);
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
int tracepoint_probe_unregister_noupdate(const char *name, void *probe)
{
	void *old;

	mutex_lock(&tracepoints_mutex);
	old = tracepoint_remove_probe(name, probe);
	if (IS_ERR(old)) {
		mutex_unlock(&tracepoints_mutex);
		return PTR_ERR(old);
	}
	tracepoint_add_old_probes(old);
	mutex_unlock(&tracepoints_mutex);
	return 0;
}
//ust// EXPORT_SYMBOL_GPL(tracepoint_probe_unregister_noupdate);

/**
 * tracepoint_probe_update_all -  update tracepoints
 */
void tracepoint_probe_update_all(void)
{
	LIST_HEAD(release_probes);
	struct tp_probes *pos, *next;

	mutex_lock(&tracepoints_mutex);
	if (!need_update) {
		mutex_unlock(&tracepoints_mutex);
		return;
	}
	if (!list_empty(&old_probes))
		list_replace_init(&old_probes, &release_probes);
	need_update = 0;
	mutex_unlock(&tracepoints_mutex);

	tracepoint_update_probes();
	list_for_each_entry_safe(pos, next, &release_probes, u.list) {
		list_del(&pos->u.list);
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

//ust//	mutex_lock(&module_mutex);
	list_for_each_entry(iter_lib, &libs, list) {
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
//ust//	mutex_unlock(&module_mutex);
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
int tracepoint_get_iter_range(struct tracepoint **tracepoint,
	struct tracepoint *begin, struct tracepoint *end)
{
	if (!*tracepoint && begin != end) {
		*tracepoint = begin;
		return 1;
	}
	if (*tracepoint >= begin && *tracepoint < end)
		return 1;
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

static void new_tracepoints(struct tracepoint *start, struct tracepoint *end)
{
	if(new_tracepoint_cb) {
		struct tracepoint *t;
		for(t=start; t < end; t++) {
			new_tracepoint_cb(t);
		}
	}
}

int tracepoint_register_lib(struct tracepoint *tracepoints_start, int tracepoints_count)
{
	struct tracepoint_lib *pl;

	pl = (struct tracepoint_lib *) malloc(sizeof(struct tracepoint_lib));

	pl->tracepoints_start = tracepoints_start;
	pl->tracepoints_count = tracepoints_count;

	/* FIXME: maybe protect this with its own mutex? */
	mutex_lock(&tracepoints_mutex);
	list_add(&pl->list, &libs);
	mutex_unlock(&tracepoints_mutex);

	new_tracepoints(tracepoints_start, tracepoints_start + tracepoints_count);

	/* FIXME: update just the loaded lib */
	lib_update_tracepoints();

	DBG("just registered a tracepoints section from %p and having %d tracepoints", tracepoints_start, tracepoints_count);
	
	return 0;
}

int tracepoint_unregister_lib(struct tracepoint *tracepoints_start, int tracepoints_count)
{
	/*FIXME: implement; but before implementing, tracepoint_register_lib must
          have appropriate locking. */

	return 0;
}
