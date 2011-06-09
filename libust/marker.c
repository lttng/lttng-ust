/*
 * Copyright (C) 2007-2011 Mathieu Desnoyers
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
 */

#define _LGPL_SOURCE
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <urcu-call-rcu.h>
#include <urcu-bp.h>
#include <urcu/rculist.h>
#include <urcu/hlist.h>

#include <ust/core.h>
#include <ust/marker.h>
#include <ust/marker-internal.h>
#include <ust/tracepoint.h>
#include <ust/tracepoint-internal.h>

#include "usterr_signal_safe.h"
#include "channels.h"
#include "tracercore.h"
#include "tracer.h"

extern struct ust_marker * const __start___ust_marker_ptrs[] __attribute__((visibility("hidden")));
extern struct ust_marker * const __stop___ust_marker_ptrs[] __attribute__((visibility("hidden")));

/* Set to 1 to enable ust_marker debug output */
static const int ust_marker_debug;
static int initialized;
static void (*new_ust_marker_cb)(struct ust_marker *);

/*
 * ust_marker mutex protects the builtin and module ust_marker and the
 * hash table, as well as the ust_marker_libs list.
 */
static DEFINE_MUTEX(ust_marker_mutex);
static CDS_LIST_HEAD(ust_marker_libs);

/*
 * Allow nested mutex for mutex listing and nested enable.
 */
static __thread int nested_mutex;

void lock_ust_marker(void)
{
	if (!(nested_mutex++))
		pthread_mutex_lock(&ust_marker_mutex);
}

void unlock_ust_marker(void)
{
	if (!(--nested_mutex))
		pthread_mutex_unlock(&ust_marker_mutex);
}

/*
 * ust_marker hash table, containing the active ust_marker.
 * Protected by ust_marker mutex.
 */
#define UST_MARKER_HASH_BITS 6
#define UST_MARKER_TABLE_SIZE (1 << UST_MARKER_HASH_BITS)
static struct cds_hlist_head ust_marker_table[UST_MARKER_TABLE_SIZE];

struct ust_marker_probe_array {
	struct rcu_head rcu;
	struct ust_marker_probe_closure c[0];
};

/*
 * Note about RCU :
 * It is used to make sure every handler has finished using its private
 * data between two consecutive operation (add or remove) on a given
 * ust_marker.  It is also used to delay the free of multiple probes
 * array until a quiescent state is reached.  ust_marker entries
 * modifications are protected by the ust_marker_mutex.
 */
struct ust_marker_entry {
	struct cds_hlist_node hlist;
	char *format;
	char *name;
			/* Probe wrapper */
	void (*call)(const struct ust_marker *mdata, void *call_private, ...);
	struct ust_marker_probe_closure single;
	struct ust_marker_probe_array *multi;
	int refcount;	/* Number of times armed. 0 if disarmed. */
	u16 channel_id;
	u16 event_id;
	unsigned char ptype:1;
	unsigned char format_allocated:1;
	char channel[0];	/* Contains channel'\0'name'\0'format'\0' */
};

/**
 * __ust_marker_empty_function - Empty probe callback
 * @mdata: ust_marker data
 * @probe_private: probe private data
 * @call_private: call site private data
 * @fmt: format string
 * @...: variable argument list
 *
 * Empty callback provided as a probe to the ust_marker. By providing
 * this to a disabled ust_marker, we make sure the  execution flow is
 * always valid even though the function pointer change and the
 * ust_marker enabling are two distinct operations that modifies the
 * execution flow of preemptible code.
 */
notrace void __ust_marker_empty_function(const struct ust_marker *mdata,
	void *probe_private, void *call_private, const char *fmt, va_list *args)
{
}

/*
 * ust_marker_probe_cb Callback that prepares the variable argument list for probes.
 * @mdata: pointer of type struct ust_marker
 * @call_private: caller site private data
 * @...:  Variable argument list.
 *
 * Since we do not use "typical" pointer based RCU in the 1 argument case, we
 * need to put a full cmm_smp_rmb() in this branch. This is why we do not use
 * rcu_dereference() for the pointer read.
 */
notrace void ust_marker_probe_cb(const struct ust_marker *mdata,
		void *call_private, ...)
{
	va_list args;
	char ptype;

	/*
	 * rcu_read_lock_sched does two things : disabling preemption to make
	 * sure the teardown of the callbacks can be done correctly when they
	 * are in modules and they insure RCU read coherency.
	 */
	rcu_read_lock();
	ptype = mdata->ptype;
	if (likely(!ptype)) {
		ust_marker_probe_func *func;
		/* Must read the ptype before ptr. They are not data dependant,
		 * so we put an explicit cmm_smp_rmb() here. */
		cmm_smp_rmb();
		func = mdata->single.func;
		/* Must read the ptr before private data. They are not data
		 * dependant, so we put an explicit cmm_smp_rmb() here. */
		cmm_smp_rmb();
		va_start(args, call_private);
		func(mdata, mdata->single.probe_private, call_private,
			mdata->format, &args);
		va_end(args);
	} else {
		struct ust_marker_probe_array *multi;
		int i;
		/*
		 * Read mdata->ptype before mdata->multi.
		 */
		cmm_smp_rmb();
		multi = mdata->multi;
		/*
		 * multi points to an array, therefore accessing the array
		 * depends on reading multi. However, even in this case,
		 * we must insure that the pointer is read _before_ the array
		 * data. Same as rcu_dereference, but we need a full cmm_smp_rmb()
		 * in the fast path, so put the explicit cmm_barrier here.
		 */
		cmm_smp_read_barrier_depends();
		for (i = 0; multi->c[i].func; i++) {
			va_start(args, call_private);
			multi->c[i].func(mdata, multi->c[i].probe_private,
				call_private, mdata->format, &args);
			va_end(args);
		}
	}
	rcu_read_unlock();
}

/*
 * ust_marker_probe_cb Callback that does not prepare the variable argument list.
 * @mdata: pointer of type struct ust_marker
 * @call_private: caller site private data
 * @...:  Variable argument list.
 *
 * Should be connected to ust_marker "UST_MARKER_NOARGS".
 */
static notrace void ust_marker_probe_cb_noarg(const struct ust_marker *mdata,
		void *call_private, ...)
{
	va_list args;	/* not initialized */
	char ptype;

	rcu_read_lock();
	ptype = mdata->ptype;
	if (likely(!ptype)) {
		ust_marker_probe_func *func;
		/* Must read the ptype before ptr. They are not data dependant,
		 * so we put an explicit cmm_smp_rmb() here. */
		cmm_smp_rmb();
		func = mdata->single.func;
		/* Must read the ptr before private data. They are not data
		 * dependant, so we put an explicit cmm_smp_rmb() here. */
		cmm_smp_rmb();
		func(mdata, mdata->single.probe_private, call_private,
			mdata->format, &args);
	} else {
		struct ust_marker_probe_array *multi;
		int i;
		/*
		 * Read mdata->ptype before mdata->multi.
		 */
		cmm_smp_rmb();
		multi = mdata->multi;
		/*
		 * multi points to an array, therefore accessing the array
		 * depends on reading multi. However, even in this case,
		 * we must insure that the pointer is read _before_ the array
		 * data. Same as rcu_dereference, but we need a full cmm_smp_rmb()
		 * in the fast path, so put the explicit cmm_barrier here.
		 */
		cmm_smp_read_barrier_depends();
		for (i = 0; multi->c[i].func; i++)
			multi->c[i].func(mdata, multi->c[i].probe_private,
				call_private, mdata->format, &args);
	}
	rcu_read_unlock();
}

static void free_old_closure(struct rcu_head *head)
{
	struct ust_marker_probe_array *multi =
		_ust_container_of(head, struct ust_marker_probe_array, rcu);
	free(multi);
}

static void debug_print_probes(struct ust_marker_entry *entry)
{
	int i;

	if (!ust_marker_debug)
		return;

	if (!entry->ptype) {
		DBG("Single probe : %p %p",
			entry->single.func,
			entry->single.probe_private);
	} else {
		for (i = 0; entry->multi->c[i].func; i++)
			DBG("Multi probe %d : %p %p", i,
				entry->multi->c[i].func,
				entry->multi->c[i].probe_private);
	}
}

static struct ust_marker_probe_array *
ust_marker_entry_add_probe(struct ust_marker_entry *entry,
		ust_marker_probe_func *probe, void *probe_private)
{
	int nr_probes = 0;
	struct ust_marker_probe_array *old, *new;

	WARN_ON(!probe);

	debug_print_probes(entry);
	old = entry->multi;
	if (!entry->ptype) {
		if (entry->single.func == probe &&
				entry->single.probe_private == probe_private)
			return ERR_PTR(-EBUSY);
		if (entry->single.func == __ust_marker_empty_function) {
			/* 0 -> 1 probes */
			entry->single.func = probe;
			entry->single.probe_private = probe_private;
			entry->refcount = 1;
			entry->ptype = 0;
			debug_print_probes(entry);
			return NULL;
		} else {
			/* 1 -> 2 probes */
			nr_probes = 1;
			old = NULL;
		}
	} else {
		/* (N -> N+1), (N != 0, 1) probes */
		for (nr_probes = 0; old->c[nr_probes].func; nr_probes++)
			if (old->c[nr_probes].func == probe
					&& old->c[nr_probes].probe_private
						== probe_private)
				return ERR_PTR(-EBUSY);
	}
	/* + 2 : one for new probe, one for NULL func */
	new = zmalloc(sizeof(struct ust_marker_probe_array)
		      + ((nr_probes + 2) * sizeof(struct ust_marker_probe_closure)));
	if (new == NULL)
		return ERR_PTR(-ENOMEM);
	if (!old)
		new->c[0] = entry->single;
	else
		memcpy(&new->c[0], &old->c[0],
			nr_probes * sizeof(struct ust_marker_probe_closure));
	new->c[nr_probes].func = probe;
	new->c[nr_probes].probe_private = probe_private;
	entry->refcount = nr_probes + 1;
	entry->multi = new;
	entry->ptype = 1;
	debug_print_probes(entry);
	return old;
}

static struct ust_marker_probe_array *
ust_marker_entry_remove_probe(struct ust_marker_entry *entry,
		ust_marker_probe_func *probe, void *probe_private)
{
	int nr_probes = 0, nr_del = 0, i;
	struct ust_marker_probe_array *old, *new;

	old = entry->multi;

	debug_print_probes(entry);
	if (!entry->ptype) {
		/* 0 -> N is an error */
		WARN_ON(entry->single.func == __ust_marker_empty_function);
		/* 1 -> 0 probes */
		WARN_ON(probe && entry->single.func != probe);
		WARN_ON(entry->single.probe_private != probe_private);
		entry->single.func = __ust_marker_empty_function;
		entry->refcount = 0;
		entry->ptype = 0;
		debug_print_probes(entry);
		return NULL;
	} else {
		/* (N -> M), (N > 1, M >= 0) probes */
		for (nr_probes = 0; old->c[nr_probes].func; nr_probes++) {
			if ((!probe || old->c[nr_probes].func == probe)
					&& old->c[nr_probes].probe_private
						== probe_private)
				nr_del++;
		}
	}

	if (nr_probes - nr_del == 0) {
		/* N -> 0, (N > 1) */
		entry->single.func = __ust_marker_empty_function;
		entry->refcount = 0;
		entry->ptype = 0;
	} else if (nr_probes - nr_del == 1) {
		/* N -> 1, (N > 1) */
		for (i = 0; old->c[i].func; i++)
			if ((probe && old->c[i].func != probe) ||
					old->c[i].probe_private != probe_private)
				entry->single = old->c[i];
		entry->refcount = 1;
		entry->ptype = 0;
	} else {
		int j = 0;
		/* N -> M, (N > 1, M > 1) */
		/* + 1 for NULL */
		new = zmalloc(sizeof(struct ust_marker_probe_array)
			      + ((nr_probes - nr_del + 1) * sizeof(struct ust_marker_probe_closure)));
		if (new == NULL)
			return ERR_PTR(-ENOMEM);
		for (i = 0; old->c[i].func; i++)
			if ((probe && old->c[i].func != probe) ||
					old->c[i].probe_private != probe_private)
				new->c[j++] = old->c[i];
		entry->refcount = nr_probes - nr_del;
		entry->ptype = 1;
		entry->multi = new;
	}
	debug_print_probes(entry);
	return old;
}

/*
 * Get ust_marker if the ust_marker is present in the ust_marker hash table.
 * Must be called with ust_marker_mutex held.
 * Returns NULL if not present.
 */
static struct ust_marker_entry *get_ust_marker(const char *channel, const char *name)
{
	struct cds_hlist_head *head;
	struct cds_hlist_node *node;
	struct ust_marker_entry *e;
	size_t channel_len = strlen(channel) + 1;
	size_t name_len = strlen(name) + 1;
	u32 hash;

	hash = jhash(channel, channel_len-1, 0) ^ jhash(name, name_len-1, 0);
	head = &ust_marker_table[hash & ((1 << UST_MARKER_HASH_BITS)-1)];
	cds_hlist_for_each_entry(e, node, head, hlist) {
		if (!strcmp(channel, e->channel) && !strcmp(name, e->name))
			return e;
	}
	return NULL;
}

/*
 * Add the ust_marker to the ust_marker hash table. Must be called with
 * ust_marker_mutex held.
 */
static struct ust_marker_entry *add_ust_marker(const char *channel, const char *name,
		const char *format)
{
	struct cds_hlist_head *head;
	struct cds_hlist_node *node;
	struct ust_marker_entry *e;
	size_t channel_len = strlen(channel) + 1;
	size_t name_len = strlen(name) + 1;
	size_t format_len = 0;
	u32 hash;

	hash = jhash(channel, channel_len-1, 0) ^ jhash(name, name_len-1, 0);
	if (format)
		format_len = strlen(format) + 1;
	head = &ust_marker_table[hash & ((1 << UST_MARKER_HASH_BITS)-1)];
	cds_hlist_for_each_entry(e, node, head, hlist) {
		if (!strcmp(channel, e->channel) && !strcmp(name, e->name)) {
			DBG("ust_marker %s.%s busy", channel, name);
			return ERR_PTR(-EBUSY);	/* Already there */
		}
	}
	/*
	 * Using zmalloc here to allocate a variable length element. Could
	 * cause some memory fragmentation if overused.
	 */
	e = zmalloc(sizeof(struct ust_marker_entry)
		    + channel_len + name_len + format_len);
	if (!e)
		return ERR_PTR(-ENOMEM);
	memcpy(e->channel, channel, channel_len);
	e->name = &e->channel[channel_len];
	memcpy(e->name, name, name_len);
	if (format) {
		e->format = &e->name[name_len];
		memcpy(e->format, format, format_len);
		if (strcmp(e->format, UST_MARKER_NOARGS) == 0)
			e->call = ust_marker_probe_cb_noarg;
		else
			e->call = ust_marker_probe_cb;
		__ust_marker(metadata, core_marker_format, NULL,
			   "channel %s name %s format %s",
			   e->channel, e->name, e->format);
	} else {
		e->format = NULL;
		e->call = ust_marker_probe_cb;
	}
	e->single.func = __ust_marker_empty_function;
	e->single.probe_private = NULL;
	e->multi = NULL;
	e->ptype = 0;
	e->format_allocated = 0;
	e->refcount = 0;
	cds_hlist_add_head(&e->hlist, head);
	return e;
}

/*
 * Remove the ust_marker from the ust_marker hash table. Must be called with mutex_lock
 * held.
 */
static int remove_ust_marker(const char *channel, const char *name)
{
	struct cds_hlist_head *head;
	struct cds_hlist_node *node;
	struct ust_marker_entry *e;
	int found = 0;
	size_t channel_len = strlen(channel) + 1;
	size_t name_len = strlen(name) + 1;
	u32 hash;
	int ret;

	hash = jhash(channel, channel_len-1, 0) ^ jhash(name, name_len-1, 0);
	head = &ust_marker_table[hash & ((1 << UST_MARKER_HASH_BITS)-1)];
	cds_hlist_for_each_entry(e, node, head, hlist) {
		if (!strcmp(channel, e->channel) && !strcmp(name, e->name)) {
			found = 1;
			break;
		}
	}
	if (!found)
		return -ENOENT;
	if (e->single.func != __ust_marker_empty_function)
		return -EBUSY;
	cds_hlist_del(&e->hlist);
	if (e->format_allocated)
		free(e->format);
	ret = ltt_channels_unregister(e->channel);
	WARN_ON(ret);
	free(e);
	return 0;
}

/*
 * Set the mark_entry format to the format found in the element.
 */
static int ust_marker_set_format(struct ust_marker_entry *entry, const char *format)
{
	entry->format = strdup(format);
	if (!entry->format)
		return -ENOMEM;
	entry->format_allocated = 1;

	__ust_marker(metadata, core_marker_format, NULL,
		   "channel %s name %s format %s",
		   entry->channel, entry->name, entry->format);
	return 0;
}

/*
 * Sets the probe callback corresponding to one ust_marker.
 */
static int set_ust_marker(struct ust_marker_entry *entry, struct ust_marker *elem,
		int active)
{
	int ret = 0;
	WARN_ON(strcmp(entry->name, elem->name) != 0);

	if (entry->format) {
		if (strcmp(entry->format, elem->format) != 0) {
			ERR("Format mismatch for probe %s (%s), ust_marker (%s)",
				entry->name,
				entry->format,
				elem->format);
			return -EPERM;
		}
	} else {
		ret = ust_marker_set_format(entry, elem->format);
		if (ret)
			return ret;
	}

	/*
	 * probe_cb setup (statically known) is done here. It is
	 * asynchronous with the rest of execution, therefore we only
	 * pass from a "safe" callback (with argument) to an "unsafe"
	 * callback (does not set arguments).
	 */
	elem->call = entry->call;
	elem->channel_id = entry->channel_id;
	elem->event_id = entry->event_id;
	/*
	 * Sanity check :
	 * We only update the single probe private data when the ptr is
	 * set to a _non_ single probe! (0 -> 1 and N -> 1, N != 1)
	 */
	WARN_ON(elem->single.func != __ust_marker_empty_function
		&& elem->single.probe_private != entry->single.probe_private
		&& !elem->ptype);
	elem->single.probe_private = entry->single.probe_private;
	/*
	 * Make sure the private data is valid when we update the
	 * single probe ptr.
	 */
	cmm_smp_wmb();
	elem->single.func = entry->single.func;
	/*
	 * We also make sure that the new probe callbacks array is consistent
	 * before setting a pointer to it.
	 */
	rcu_assign_pointer(elem->multi, entry->multi);
	/*
	 * Update the function or multi probe array pointer before setting the
	 * ptype.
	 */
	cmm_smp_wmb();
	elem->ptype = entry->ptype;

	if (elem->tp_name && (active ^ elem->state)) {
		WARN_ON(!elem->tp_cb);
		/*
		 * It is ok to directly call the probe registration because type
		 * checking has been done in the __ust_marker_tp() macro.
		 */

		if (active) {
			ret = tracepoint_probe_register_noupdate(
				elem->tp_name,
				elem->tp_cb, NULL);
		} else {
			/*
			 * tracepoint_probe_update_all() must be called
			 * before the library containing tp_cb is unloaded.
			 */
			ret = tracepoint_probe_unregister_noupdate(
				elem->tp_name,
				elem->tp_cb, NULL);
		}
	}
	elem->state = active;

	return ret;
}

/*
 * Disable a ust_marker and its probe callback.
 * Note: only waiting an RCU period after setting elem->call to the empty
 * function insures that the original callback is not used anymore. This insured
 * by rcu_read_lock around the call site.
 */
static void disable_ust_marker(struct ust_marker *elem)
{
	int ret;

	/* leave "call" as is. It is known statically. */
	if (elem->tp_name && elem->state) {
		WARN_ON(!elem->tp_cb);
		/*
		 * It is ok to directly call the probe registration because type
		 * checking has been done in the __ust_marker_tp() macro.
		 */
		/*
		 * tracepoint_probe_update_all() must be called
		 * before the module containing tp_cb is unloaded.
		 */
		ret = tracepoint_probe_unregister_noupdate(elem->tp_name,
			elem->tp_cb, NULL);
		WARN_ON(ret);
	}
	elem->state = 0;
	elem->single.func = __ust_marker_empty_function;
	/* Update the function before setting the ptype */
	cmm_smp_wmb();
	elem->ptype = 0;	/* single probe */
	/*
	 * Leave the private data and channel_id/event_id there, because removal
	 * is racy and should be done only after an RCU period. These are never
	 * used until the next initialization anyway.
	 */
}

/*
 * is_ust_marker_enabled - Check if a ust_marker is enabled
 * @channel: channel name
 * @name: ust_marker name
 *
 * Returns 1 if the ust_marker is enabled, 0 if disabled.
 */
int is_ust_marker_enabled(const char *channel, const char *name)
{
	struct ust_marker_entry *entry;

	lock_ust_marker();
	entry = get_ust_marker(channel, name);
	unlock_ust_marker();

	return entry && !!entry->refcount;
}

/**
 * ust_marker_update_probe_range - Update a probe range
 * @begin: beginning of the range
 * @end: end of the range
 *
 * Updates the probe callback corresponding to a range of ust_marker.
 */
static
void ust_marker_update_probe_range(struct ust_marker * const *begin,
	struct ust_marker * const *end)
{
	struct ust_marker * const *iter;
	struct ust_marker_entry *mark_entry;

	for (iter = begin; iter < end; iter++) {
		if (!*iter)
			continue;	/* skip dummy */
		mark_entry = get_ust_marker((*iter)->channel, (*iter)->name);
		if (mark_entry) {
			set_ust_marker(mark_entry, *iter, !!mark_entry->refcount);
			/*
			 * ignore error, continue
			 */
		} else {
			disable_ust_marker(*iter);
		}
	}
}

static void lib_update_ust_marker(void)
{
	struct ust_marker_lib *lib;

	lock_ust_marker();
	cds_list_for_each_entry(lib, &ust_marker_libs, list)
		ust_marker_update_probe_range(lib->ust_marker_start,
				lib->ust_marker_start + lib->ust_marker_count);
	unlock_ust_marker();
}

/*
 * Update probes, removing the faulty probes.
 *
 * Internal callback only changed before the first probe is connected to it.
 * Single probe private data can only be changed on 0 -> 1 and 2 -> 1
 * transitions.  All other transitions will leave the old private data valid.
 * This makes the non-atomicity of the callback/private data updates valid.
 *
 * "special case" updates :
 * 0 -> 1 callback
 * 1 -> 0 callback
 * 1 -> 2 callbacks
 * 2 -> 1 callbacks
 * Other updates all behave the same, just like the 2 -> 3 or 3 -> 2 updates.
 * Site effect : ust_marker_set_format may delete the ust_marker entry (creating a
 * replacement).
 */
static void ust_marker_update_probes(void)
{
	lib_update_ust_marker();
	tracepoint_probe_update_all();
}

/**
 * ust_marker_probe_register -  Connect a probe to a ust_marker
 * @channel: ust_marker channel
 * @name: ust_marker name
 * @format: format string
 * @probe: probe handler
 * @probe_private: probe private data
 *
 * private data must be a valid allocated memory address, or NULL.
 * Returns 0 if ok, error value on error.
 * The probe address must at least be aligned on the architecture pointer size.
 */
int ust_marker_probe_register(const char *channel, const char *name,
			  const char *format, ust_marker_probe_func *probe,
			  void *probe_private)
{
	struct ust_marker_entry *entry;
	int ret = 0, ret_err;
	struct ust_marker_probe_array *old;
	int first_probe = 0;

	lock_ust_marker();
	entry = get_ust_marker(channel, name);
	if (!entry) {
		first_probe = 1;
		entry = add_ust_marker(channel, name, format);
		if (IS_ERR(entry))
			ret = PTR_ERR(entry);
		if (ret)
			goto end;
		ret = ltt_channels_register(channel);
		if (ret)
			goto error_remove_ust_marker;
		ret = ltt_channels_get_index_from_name(channel);
		if (ret < 0)
			goto error_unregister_channel;
		entry->channel_id = ret;
		ret = ltt_channels_get_event_id(channel, name);
		if (ret < 0)
			goto error_unregister_channel;
		entry->event_id = ret;
		ret = 0;
		__ust_marker(metadata, core_marker_id, NULL,
			   "channel %s name %s event_id %hu "
			   "int #1u%zu long #1u%zu pointer #1u%zu "
			   "size_t #1u%zu alignment #1u%u",
			   channel, name, entry->event_id,
			   sizeof(int), sizeof(long), sizeof(void *),
			   sizeof(size_t), ltt_get_alignment());
	} else if (format) {
		if (!entry->format)
			ret = ust_marker_set_format(entry, format);
		else if (strcmp(entry->format, format))
			ret = -EPERM;
		if (ret)
			goto end;
	}

	old = ust_marker_entry_add_probe(entry, probe, probe_private);
	if (IS_ERR(old)) {
		ret = PTR_ERR(old);
		if (first_probe)
			goto error_unregister_channel;
		else
			goto end;
	}
	unlock_ust_marker();

	/* Activate ust_marker if necessary */
	ust_marker_update_probes();

	if (old) {
		synchronize_rcu();
		free_old_closure(&old->rcu);
	}
	return ret;

error_unregister_channel:
	ret_err = ltt_channels_unregister(channel);
	WARN_ON(ret_err);
error_remove_ust_marker:
	ret_err = remove_ust_marker(channel, name);
	WARN_ON(ret_err);
end:
	unlock_ust_marker();
	return ret;
}

/**
 * ust_marker_probe_unregister -  Disconnect a probe from a ust_marker
 * @channel: ust_marker channel
 * @name: ust_marker name
 * @probe: probe function pointer
 * @probe_private: probe private data
 *
 * Returns the private data given to ust_marker_probe_register, or an ERR_PTR().
 * We do not need to call a synchronize_sched to make sure the probes have
 * finished running before doing a module unload, because the module unload
 * itself uses stop_machine(), which insures that every preempt disabled section
 * have finished.
 */
int ust_marker_probe_unregister(const char *channel, const char *name,
			    ust_marker_probe_func *probe, void *probe_private)
{
	struct ust_marker_entry *entry;
	struct ust_marker_probe_array *old;
	int ret = 0;

	lock_ust_marker();
	entry = get_ust_marker(channel, name);
	if (!entry) {
		ret = -ENOENT;
		goto end;
	}
	old = ust_marker_entry_remove_probe(entry, probe, probe_private);
	unlock_ust_marker();

	ust_marker_update_probes();

	if (old) {
		synchronize_rcu();
		free_old_closure(&old->rcu);
	}
	return ret;

end:
	unlock_ust_marker();
	return ret;
}

static struct ust_marker_entry *
get_ust_marker_from_private_data(ust_marker_probe_func *probe,
				 void *probe_private)
{
	struct ust_marker_entry *entry;
	unsigned int i;
	struct cds_hlist_head *head;
	struct cds_hlist_node *node;

	for (i = 0; i < UST_MARKER_TABLE_SIZE; i++) {
		head = &ust_marker_table[i];
		cds_hlist_for_each_entry(entry, node, head, hlist) {
			if (!entry->ptype) {
				if (entry->single.func == probe
						&& entry->single.probe_private
						== probe_private)
					return entry;
			} else {
				struct ust_marker_probe_array *closure;
				closure = entry->multi;
				for (i = 0; closure->c[i].func; i++) {
					if (closure->c[i].func == probe &&
							closure->c[i].probe_private
							== probe_private)
						return entry;
				}
			}
		}
	}
	return NULL;
}

/**
 * ust_marker_probe_unregister_private_data -  Disconnect a probe from a ust_marker
 * @probe: probe function
 * @probe_private: probe private data
 *
 * Unregister a probe by providing the registered private data.
 * Only removes the first ust_marker found in hash table.
 * Return 0 on success or error value.
 * We do not need to call a synchronize_sched to make sure the probes have
 * finished running before doing a module unload, because the module unload
 * itself uses stop_machine(), which insures that every preempt disabled section
 * have finished.
 */
int ust_marker_probe_unregister_private_data(ust_marker_probe_func *probe,
		void *probe_private)
{
	struct ust_marker_entry *entry;
	int ret = 0;
	struct ust_marker_probe_array *old;
	char *channel = NULL, *name = NULL;

	lock_ust_marker();
	entry = get_ust_marker_from_private_data(probe, probe_private);
	if (!entry) {
		ret = -ENOENT;
		goto unlock;
	}
	old = ust_marker_entry_remove_probe(entry, NULL, probe_private);
	channel = strdup(entry->channel);
	name = strdup(entry->name);
	/* Ignore busy error message */
	remove_ust_marker(channel, name);
	unlock_ust_marker();

	ust_marker_update_probes();

	if (old) {
		synchronize_rcu();
		free_old_closure(&old->rcu);
	}
	goto end;

unlock:
	unlock_ust_marker();
end:
	free(channel);
	free(name);
	return ret;
}

/**
 * ust_marker_get_private_data - Get a ust_marker's probe private data
 * @channel: ust_marker channel
 * @name: ust_marker name
 * @probe: probe to match
 * @num: get the nth matching probe's private data
 *
 * Returns the nth private data pointer (starting from 0) matching, or an
 * ERR_PTR.
 * Returns the private data pointer, or an ERR_PTR.
 * The private data pointer should _only_ be dereferenced if the caller is the
 * owner of the data, or its content could vanish. This is mostly used to
 * confirm that a caller is the owner of a registered probe.
 */
void *ust_marker_get_private_data(const char *channel, const char *name,
			      ust_marker_probe_func *probe, int num)
{
	struct cds_hlist_head *head;
	struct cds_hlist_node *node;
	struct ust_marker_entry *e;
	size_t channel_len = strlen(channel) + 1;
	size_t name_len = strlen(name) + 1;
	int i;
	u32 hash;

	hash = jhash(channel, channel_len-1, 0) ^ jhash(name, name_len-1, 0);
	head = &ust_marker_table[hash & ((1 << UST_MARKER_HASH_BITS)-1)];
	cds_hlist_for_each_entry(e, node, head, hlist) {
		if (!strcmp(channel, e->channel) && !strcmp(name, e->name)) {
			if (!e->ptype) {
				if (num == 0 && e->single.func == probe)
					return e->single.probe_private;
			} else {
				struct ust_marker_probe_array *closure;
				int match = 0;
				closure = e->multi;
				for (i = 0; closure->c[i].func; i++) {
					if (closure->c[i].func != probe)
						continue;
					if (match++ == num)
						return closure->c[i].probe_private;
				}
			}
			break;
		}
	}
	return ERR_PTR(-ENOENT);
}

/**
 * ust_marker_get_iter_range - Get a next ust_marker iterator given a range.
 * @ust_marker: current ust_marker (in), next ust_marker (out)
 * @begin: beginning of the range
 * @end: end of the range
 *
 * Returns whether a next ust_marker has been found (1) or not (0).
 * Will return the first ust_marker in the range if the input ust_marker is NULL.
 * Called with markers mutex held.
 */
static
int ust_marker_get_iter_range(struct ust_marker * const **ust_marker,
	struct ust_marker * const *begin,
	struct ust_marker * const *end)
{
	if (!*ust_marker && begin != end)
		*ust_marker = begin;
	while (*ust_marker >= begin && *ust_marker < end) {
		if (!**ust_marker)
			(*ust_marker)++;	/* skip dummy */
		else
			return 1;
	}
	return 0;
}

/*
 * Returns 0 if current not found.
 * Returns 1 if current found.
 * Called with markers mutex held.
 */
static
int lib_get_iter_ust_marker(struct ust_marker_iter *iter)
{
	struct ust_marker_lib *iter_lib;
	int found = 0;

	cds_list_for_each_entry(iter_lib, &ust_marker_libs, list) {
		if (iter_lib < iter->lib)
			continue;
		else if (iter_lib > iter->lib)
			iter->ust_marker = NULL;
		found = ust_marker_get_iter_range(&iter->ust_marker,
			iter_lib->ust_marker_start,
			iter_lib->ust_marker_start + iter_lib->ust_marker_count);
		if (found) {
			iter->lib = iter_lib;
			break;
		}
	}
	return found;
}

/* Called with markers mutex held. */
static void ust_marker_get_iter(struct ust_marker_iter *iter)
{
	int found = 0;

	found = lib_get_iter_ust_marker(iter);
	if (!found)
		ust_marker_iter_reset(iter);
}

void ust_marker_iter_start(struct ust_marker_iter *iter)
{
	lock_ust_marker();
	ust_marker_get_iter(iter);
}

/* Called with markers mutex held. */
void ust_marker_iter_next(struct ust_marker_iter *iter)
{
	iter->ust_marker++;
	/*
	 * iter->ust_marker may be invalid because we blindly incremented it.
	 * Make sure it is valid by marshalling on the ust_marker, getting the
	 * ust_marker from following modules if necessary.
	 */
	ust_marker_get_iter(iter);
}

void ust_marker_iter_stop(struct ust_marker_iter *iter)
{
	unlock_ust_marker();
}

void ust_marker_iter_reset(struct ust_marker_iter *iter)
{
	iter->lib = NULL;
	iter->ust_marker = NULL;
}

void ltt_dump_ust_marker_state(struct ust_trace *trace)
{
	struct ust_marker_entry *entry;
	struct ltt_probe_private_data call_data;
	struct cds_hlist_head *head;
	struct cds_hlist_node *node;
	unsigned int i;

	lock_ust_marker();
	call_data.trace = trace;
	call_data.serializer = NULL;

	for (i = 0; i < UST_MARKER_TABLE_SIZE; i++) {
		head = &ust_marker_table[i];
		cds_hlist_for_each_entry(entry, node, head, hlist) {
			__ust_marker(metadata, core_marker_id,
				&call_data,
				"channel %s name %s event_id %hu "
				"int #1u%zu long #1u%zu pointer #1u%zu "
				"size_t #1u%zu alignment #1u%u",
				entry->channel,
				entry->name,
				entry->event_id,
				sizeof(int), sizeof(long),
				sizeof(void *), sizeof(size_t),
				ltt_get_alignment());
			if (entry->format)
				__ust_marker(metadata,
					core_marker_format,
					&call_data,
					"channel %s name %s format %s",
					entry->channel,
					entry->name,
					entry->format);
		}
	}
	unlock_ust_marker();
}

void ust_marker_set_new_ust_marker_cb(void (*cb)(struct ust_marker *))
{
	new_ust_marker_cb = cb;
}

static void new_ust_marker(struct ust_marker * const *start,
			   struct ust_marker * const *end)
{
	if (new_ust_marker_cb) {
		struct ust_marker * const *m;

		for (m = start; m < end; m++) {
			if (*m)
				new_ust_marker_cb(*m);
		}
	}
}

int ust_marker_register_lib(struct ust_marker * const *ust_marker_start,
			    int ust_marker_count)
{
	struct ust_marker_lib *pl, *iter;

	pl = (struct ust_marker_lib *) zmalloc(sizeof(struct ust_marker_lib));

	pl->ust_marker_start = ust_marker_start;
	pl->ust_marker_count = ust_marker_count;

	lock_ust_marker();

	/*
	 * We sort the libs by struct lib pointer address.
	 */
	cds_list_for_each_entry_reverse(iter, &ust_marker_libs, list) {
		BUG_ON(iter == pl);    /* Should never be in the list twice */
		if (iter < pl) {
			/* We belong to the location right after iter. */
			cds_list_add(&pl->list, &iter->list);
			goto lib_added;
		}
	}
	/* We should be added at the head of the list */
	cds_list_add(&pl->list, &ust_marker_libs);
lib_added:
	unlock_ust_marker();

	new_ust_marker(ust_marker_start, ust_marker_start + ust_marker_count);

	/* TODO: update just the loaded lib */
	lib_update_ust_marker();

	DBG("just registered a ust_marker section from %p and having %d ust_marker (minus dummy ust_marker)", ust_marker_start, ust_marker_count);
	
	return 0;
}

int ust_marker_unregister_lib(struct ust_marker * const *ust_marker_start)
{
	struct ust_marker_lib *lib;

	lock_ust_marker();
	cds_list_for_each_entry(lib, &ust_marker_libs, list) {
		if(lib->ust_marker_start == ust_marker_start) {
			struct ust_marker_lib *lib2free = lib;
			cds_list_del(&lib->list);
			free(lib2free);
			break;
		}
	}
	unlock_ust_marker();

	return 0;
}

void __attribute__((constructor)) init_ust_marker(void)
{
	if (!initialized) {
		init_tracepoint();
		ust_marker_register_lib(__start___ust_marker_ptrs,
			__stop___ust_marker_ptrs
			- __start___ust_marker_ptrs);
		initialized = 1;
	}
}

void __attribute__((destructor)) destroy_ust_marker(void)
{
	ust_marker_unregister_lib(__start___ust_marker_ptrs);
}
