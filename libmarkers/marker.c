/*
 * Copyright (C) 2007 Mathieu Desnoyers
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
//ust// #include <linux/module.h>
//ust// #include <linux/mutex.h>
//ust// #include <linux/types.h>
#include "jhash.h"
#include "list.h"
#include "rcupdate.h"
//ust// #include <linux/marker.h>
#include <errno.h>
//ust// #include <linux/slab.h>
//ust// #include <linux/immediate.h>
//ust// #include <linux/sched.h>
//ust// #include <linux/uaccess.h>
//ust// #include <linux/user_marker.h>
//ust// #include <linux/ltt-tracer.h>

#include "marker.h"
#include "kernelcompat.h"
#include "usterr.h"
#include "channels.h"
#include "tracercore.h"
#include "tracer.h"

extern struct marker __start___markers[] __attribute__((visibility("hidden")));
extern struct marker __stop___markers[] __attribute__((visibility("hidden")));

/* Set to 1 to enable marker debug output */
static const int marker_debug;

/*
 * markers_mutex nests inside module_mutex. Markers mutex protects the builtin
 * and module markers and the hash table.
 */
static DEFINE_MUTEX(markers_mutex);

void lock_markers(void)
{
	mutex_lock(&markers_mutex);
}

void unlock_markers(void)
{
	mutex_unlock(&markers_mutex);
}

/*
 * Marker hash table, containing the active markers.
 * Protected by module_mutex.
 */
#define MARKER_HASH_BITS 6
#define MARKER_TABLE_SIZE (1 << MARKER_HASH_BITS)
static struct hlist_head marker_table[MARKER_TABLE_SIZE];

/*
 * Note about RCU :
 * It is used to make sure every handler has finished using its private data
 * between two consecutive operation (add or remove) on a given marker.  It is
 * also used to delay the free of multiple probes array until a quiescent state
 * is reached.
 * marker entries modifications are protected by the markers_mutex.
 */
struct marker_entry {
	struct hlist_node hlist;
	char *format;
	char *name;
			/* Probe wrapper */
	void (*call)(const struct marker *mdata, void *call_private, ...);
	struct marker_probe_closure single;
	struct marker_probe_closure *multi;
	int refcount;	/* Number of times armed. 0 if disarmed. */
	struct rcu_head rcu;
	void *oldptr;
	int rcu_pending;
	u16 channel_id;
	u16 event_id;
	unsigned char ptype:1;
	unsigned char format_allocated:1;
	char channel[0];	/* Contains channel'\0'name'\0'format'\0' */
};

#ifdef CONFIG_MARKERS_USERSPACE
static void marker_update_processes(void);
#else
static void marker_update_processes(void)
{
}
#endif

/**
 * __mark_empty_function - Empty probe callback
 * @mdata: marker data
 * @probe_private: probe private data
 * @call_private: call site private data
 * @fmt: format string
 * @...: variable argument list
 *
 * Empty callback provided as a probe to the markers. By providing this to a
 * disabled marker, we make sure the  execution flow is always valid even
 * though the function pointer change and the marker enabling are two distinct
 * operations that modifies the execution flow of preemptible code.
 */
notrace void __mark_empty_function(const struct marker *mdata,
	void *probe_private, void *call_private, const char *fmt, va_list *args)
{
}
//ust// EXPORT_SYMBOL_GPL(__mark_empty_function);

/*
 * marker_probe_cb Callback that prepares the variable argument list for probes.
 * @mdata: pointer of type struct marker
 * @call_private: caller site private data
 * @...:  Variable argument list.
 *
 * Since we do not use "typical" pointer based RCU in the 1 argument case, we
 * need to put a full smp_rmb() in this branch. This is why we do not use
 * rcu_dereference() for the pointer read.
 */
notrace void marker_probe_cb(const struct marker *mdata,
		void *call_private, ...)
{
	va_list args;
	char ptype;

	/*
	 * rcu_read_lock_sched does two things : disabling preemption to make
	 * sure the teardown of the callbacks can be done correctly when they
	 * are in modules and they insure RCU read coherency.
	 */
//ust//	rcu_read_lock_sched_notrace();
	ptype = mdata->ptype;
	if (likely(!ptype)) {
		marker_probe_func *func;
		/* Must read the ptype before ptr. They are not data dependant,
		 * so we put an explicit smp_rmb() here. */
		smp_rmb();
		func = mdata->single.func;
		/* Must read the ptr before private data. They are not data
		 * dependant, so we put an explicit smp_rmb() here. */
		smp_rmb();
		va_start(args, call_private);
		func(mdata, mdata->single.probe_private, call_private,
			mdata->format, &args);
		va_end(args);
	} else {
		struct marker_probe_closure *multi;
		int i;
		/*
		 * Read mdata->ptype before mdata->multi.
		 */
		smp_rmb();
		multi = mdata->multi;
		/*
		 * multi points to an array, therefore accessing the array
		 * depends on reading multi. However, even in this case,
		 * we must insure that the pointer is read _before_ the array
		 * data. Same as rcu_dereference, but we need a full smp_rmb()
		 * in the fast path, so put the explicit barrier here.
		 */
		smp_read_barrier_depends();
		for (i = 0; multi[i].func; i++) {
			va_start(args, call_private);
			multi[i].func(mdata, multi[i].probe_private,
				call_private, mdata->format, &args);
			va_end(args);
		}
	}
//ust//	rcu_read_unlock_sched_notrace();
}
//ust// EXPORT_SYMBOL_GPL(marker_probe_cb);

/*
 * marker_probe_cb Callback that does not prepare the variable argument list.
 * @mdata: pointer of type struct marker
 * @call_private: caller site private data
 * @...:  Variable argument list.
 *
 * Should be connected to markers "MARK_NOARGS".
 */
static notrace void marker_probe_cb_noarg(const struct marker *mdata,
		void *call_private, ...)
{
	va_list args;	/* not initialized */
	char ptype;

//ust//	rcu_read_lock_sched_notrace();
	ptype = mdata->ptype;
	if (likely(!ptype)) {
		marker_probe_func *func;
		/* Must read the ptype before ptr. They are not data dependant,
		 * so we put an explicit smp_rmb() here. */
		smp_rmb();
		func = mdata->single.func;
		/* Must read the ptr before private data. They are not data
		 * dependant, so we put an explicit smp_rmb() here. */
		smp_rmb();
		func(mdata, mdata->single.probe_private, call_private,
			mdata->format, &args);
	} else {
		struct marker_probe_closure *multi;
		int i;
		/*
		 * Read mdata->ptype before mdata->multi.
		 */
		smp_rmb();
		multi = mdata->multi;
		/*
		 * multi points to an array, therefore accessing the array
		 * depends on reading multi. However, even in this case,
		 * we must insure that the pointer is read _before_ the array
		 * data. Same as rcu_dereference, but we need a full smp_rmb()
		 * in the fast path, so put the explicit barrier here.
		 */
		smp_read_barrier_depends();
		for (i = 0; multi[i].func; i++)
			multi[i].func(mdata, multi[i].probe_private,
				call_private, mdata->format, &args);
	}
//ust//	rcu_read_unlock_sched_notrace();
}

static void free_old_closure(struct rcu_head *head)
{
	struct marker_entry *entry = container_of(head,
		struct marker_entry, rcu);
	kfree(entry->oldptr);
	/* Make sure we free the data before setting the pending flag to 0 */
	smp_wmb();
	entry->rcu_pending = 0;
}

static void debug_print_probes(struct marker_entry *entry)
{
	int i;

	if (!marker_debug)
		return;

	if (!entry->ptype) {
		printk(KERN_DEBUG "Single probe : %p %p\n",
			entry->single.func,
			entry->single.probe_private);
	} else {
		for (i = 0; entry->multi[i].func; i++)
			printk(KERN_DEBUG "Multi probe %d : %p %p\n", i,
				entry->multi[i].func,
				entry->multi[i].probe_private);
	}
}

static struct marker_probe_closure *
marker_entry_add_probe(struct marker_entry *entry,
		marker_probe_func *probe, void *probe_private)
{
	int nr_probes = 0;
	struct marker_probe_closure *old, *new;

	WARN_ON(!probe);

	debug_print_probes(entry);
	old = entry->multi;
	if (!entry->ptype) {
		if (entry->single.func == probe &&
				entry->single.probe_private == probe_private)
			return ERR_PTR(-EBUSY);
		if (entry->single.func == __mark_empty_function) {
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
		for (nr_probes = 0; old[nr_probes].func; nr_probes++)
			if (old[nr_probes].func == probe
					&& old[nr_probes].probe_private
						== probe_private)
				return ERR_PTR(-EBUSY);
	}
	/* + 2 : one for new probe, one for NULL func */
	new = kzalloc((nr_probes + 2) * sizeof(struct marker_probe_closure),
			GFP_KERNEL);
	if (new == NULL)
		return ERR_PTR(-ENOMEM);
	if (!old)
		new[0] = entry->single;
	else
		memcpy(new, old,
			nr_probes * sizeof(struct marker_probe_closure));
	new[nr_probes].func = probe;
	new[nr_probes].probe_private = probe_private;
	entry->refcount = nr_probes + 1;
	entry->multi = new;
	entry->ptype = 1;
	debug_print_probes(entry);
	return old;
}

static struct marker_probe_closure *
marker_entry_remove_probe(struct marker_entry *entry,
		marker_probe_func *probe, void *probe_private)
{
	int nr_probes = 0, nr_del = 0, i;
	struct marker_probe_closure *old, *new;

	old = entry->multi;

	debug_print_probes(entry);
	if (!entry->ptype) {
		/* 0 -> N is an error */
		WARN_ON(entry->single.func == __mark_empty_function);
		/* 1 -> 0 probes */
		WARN_ON(probe && entry->single.func != probe);
		WARN_ON(entry->single.probe_private != probe_private);
		entry->single.func = __mark_empty_function;
		entry->refcount = 0;
		entry->ptype = 0;
		debug_print_probes(entry);
		return NULL;
	} else {
		/* (N -> M), (N > 1, M >= 0) probes */
		for (nr_probes = 0; old[nr_probes].func; nr_probes++) {
			if ((!probe || old[nr_probes].func == probe)
					&& old[nr_probes].probe_private
						== probe_private)
				nr_del++;
		}
	}

	if (nr_probes - nr_del == 0) {
		/* N -> 0, (N > 1) */
		entry->single.func = __mark_empty_function;
		entry->refcount = 0;
		entry->ptype = 0;
	} else if (nr_probes - nr_del == 1) {
		/* N -> 1, (N > 1) */
		for (i = 0; old[i].func; i++)
			if ((probe && old[i].func != probe) ||
					old[i].probe_private != probe_private)
				entry->single = old[i];
		entry->refcount = 1;
		entry->ptype = 0;
	} else {
		int j = 0;
		/* N -> M, (N > 1, M > 1) */
		/* + 1 for NULL */
		new = kzalloc((nr_probes - nr_del + 1)
			* sizeof(struct marker_probe_closure), GFP_KERNEL);
		if (new == NULL)
			return ERR_PTR(-ENOMEM);
		for (i = 0; old[i].func; i++)
			if ((probe && old[i].func != probe) ||
					old[i].probe_private != probe_private)
				new[j++] = old[i];
		entry->refcount = nr_probes - nr_del;
		entry->ptype = 1;
		entry->multi = new;
	}
	debug_print_probes(entry);
	return old;
}

/*
 * Get marker if the marker is present in the marker hash table.
 * Must be called with markers_mutex held.
 * Returns NULL if not present.
 */
static struct marker_entry *get_marker(const char *channel, const char *name)
{
	struct hlist_head *head;
	struct hlist_node *node;
	struct marker_entry *e;
	size_t channel_len = strlen(channel) + 1;
	size_t name_len = strlen(name) + 1;
	u32 hash;

	hash = jhash(channel, channel_len-1, 0) ^ jhash(name, name_len-1, 0);
	head = &marker_table[hash & ((1 << MARKER_HASH_BITS)-1)];
	hlist_for_each_entry(e, node, head, hlist) {
		if (!strcmp(channel, e->channel) && !strcmp(name, e->name))
			return e;
	}
	return NULL;
}

/*
 * Add the marker to the marker hash table. Must be called with markers_mutex
 * held.
 */
static struct marker_entry *add_marker(const char *channel, const char *name,
		const char *format)
{
	struct hlist_head *head;
	struct hlist_node *node;
	struct marker_entry *e;
	size_t channel_len = strlen(channel) + 1;
	size_t name_len = strlen(name) + 1;
	size_t format_len = 0;
	u32 hash;

	hash = jhash(channel, channel_len-1, 0) ^ jhash(name, name_len-1, 0);
	if (format)
		format_len = strlen(format) + 1;
	head = &marker_table[hash & ((1 << MARKER_HASH_BITS)-1)];
	hlist_for_each_entry(e, node, head, hlist) {
		if (!strcmp(channel, e->channel) && !strcmp(name, e->name)) {
			printk(KERN_NOTICE
				"Marker %s.%s busy\n", channel, name);
			return ERR_PTR(-EBUSY);	/* Already there */
		}
	}
	/*
	 * Using kmalloc here to allocate a variable length element. Could
	 * cause some memory fragmentation if overused.
	 */
	e = kmalloc(sizeof(struct marker_entry)
		    + channel_len + name_len + format_len,
		    GFP_KERNEL);
	if (!e)
		return ERR_PTR(-ENOMEM);
	memcpy(e->channel, channel, channel_len);
	e->name = &e->channel[channel_len];
	memcpy(e->name, name, name_len);
	if (format) {
		e->format = &e->name[channel_len + name_len];
		memcpy(e->format, format, format_len);
		if (strcmp(e->format, MARK_NOARGS) == 0)
			e->call = marker_probe_cb_noarg;
		else
			e->call = marker_probe_cb;
		trace_mark(metadata, core_marker_format,
			   "channel %s name %s format %s",
			   e->channel, e->name, e->format);
	} else {
		e->format = NULL;
		e->call = marker_probe_cb;
	}
	e->single.func = __mark_empty_function;
	e->single.probe_private = NULL;
	e->multi = NULL;
	e->ptype = 0;
	e->format_allocated = 0;
	e->refcount = 0;
	e->rcu_pending = 0;
	hlist_add_head(&e->hlist, head);
	return e;
}

/*
 * Remove the marker from the marker hash table. Must be called with mutex_lock
 * held.
 */
static int remove_marker(const char *channel, const char *name)
{
	struct hlist_head *head;
	struct hlist_node *node;
	struct marker_entry *e;
	int found = 0;
	size_t channel_len = strlen(channel) + 1;
	size_t name_len = strlen(name) + 1;
	u32 hash;
	int ret;

	hash = jhash(channel, channel_len-1, 0) ^ jhash(name, name_len-1, 0);
	head = &marker_table[hash & ((1 << MARKER_HASH_BITS)-1)];
	hlist_for_each_entry(e, node, head, hlist) {
		if (!strcmp(channel, e->channel) && !strcmp(name, e->name)) {
			found = 1;
			break;
		}
	}
	if (!found)
		return -ENOENT;
	if (e->single.func != __mark_empty_function)
		return -EBUSY;
	hlist_del(&e->hlist);
	if (e->format_allocated)
		kfree(e->format);
	ret = ltt_channels_unregister(e->channel);
	WARN_ON(ret);
	/* Make sure the call_rcu has been executed */
	if (e->rcu_pending)
		rcu_barrier_sched();
	kfree(e);
	return 0;
}

/*
 * Set the mark_entry format to the format found in the element.
 */
static int marker_set_format(struct marker_entry *entry, const char *format)
{
	entry->format = kstrdup(format, GFP_KERNEL);
	if (!entry->format)
		return -ENOMEM;
	entry->format_allocated = 1;

	trace_mark(metadata, core_marker_format,
		   "channel %s name %s format %s",
		   entry->channel, entry->name, entry->format);
	return 0;
}

/*
 * Sets the probe callback corresponding to one marker.
 */
static int set_marker(struct marker_entry *entry, struct marker *elem,
		int active)
{
	int ret = 0;
	WARN_ON(strcmp(entry->name, elem->name) != 0);

	if (entry->format) {
		if (strcmp(entry->format, elem->format) != 0) {
			printk(KERN_NOTICE
				"Format mismatch for probe %s "
				"(%s), marker (%s)\n",
				entry->name,
				entry->format,
				elem->format);
			return -EPERM;
		}
	} else {
		ret = marker_set_format(entry, elem->format);
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
	WARN_ON(elem->single.func != __mark_empty_function
		&& elem->single.probe_private != entry->single.probe_private
		&& !elem->ptype);
	elem->single.probe_private = entry->single.probe_private;
	/*
	 * Make sure the private data is valid when we update the
	 * single probe ptr.
	 */
	smp_wmb();
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
	smp_wmb();
	elem->ptype = entry->ptype;

//ust//	if (elem->tp_name && (active ^ _imv_read(elem->state))) {
//ust//		WARN_ON(!elem->tp_cb);
//ust//		/*
//ust//		 * It is ok to directly call the probe registration because type
//ust//		 * checking has been done in the __trace_mark_tp() macro.
//ust//		 */
//ust//
//ust//		if (active) {
//ust//			/*
//ust//			 * try_module_get should always succeed because we hold
//ust//			 * markers_mutex to get the tp_cb address.
//ust//			 */
//ust//			ret = try_module_get(__module_text_address(
//ust//				(unsigned long)elem->tp_cb));
//ust//			BUG_ON(!ret);
//ust//			ret = tracepoint_probe_register_noupdate(
//ust//				elem->tp_name,
//ust//				elem->tp_cb);
//ust//		} else {
//ust//			ret = tracepoint_probe_unregister_noupdate(
//ust//				elem->tp_name,
//ust//				elem->tp_cb);
//ust//			/*
//ust//			 * tracepoint_probe_update_all() must be called
//ust//			 * before the module containing tp_cb is unloaded.
//ust//			 */
//ust//			module_put(__module_text_address(
//ust//				(unsigned long)elem->tp_cb));
//ust//		}
//ust//	}
	elem->state__imv = active;

	return ret;
}

/*
 * Disable a marker and its probe callback.
 * Note: only waiting an RCU period after setting elem->call to the empty
 * function insures that the original callback is not used anymore. This insured
 * by rcu_read_lock_sched around the call site.
 */
static void disable_marker(struct marker *elem)
{
	int ret;

	/* leave "call" as is. It is known statically. */
//ust//	if (elem->tp_name && _imv_read(elem->state)) {
//ust//		WARN_ON(!elem->tp_cb);
//ust//		/*
//ust//		 * It is ok to directly call the probe registration because type
//ust//		 * checking has been done in the __trace_mark_tp() macro.
//ust//		 */
//ust//		ret = tracepoint_probe_unregister_noupdate(elem->tp_name,
//ust//			elem->tp_cb);
//ust//		WARN_ON(ret);
//ust//		/*
//ust//		 * tracepoint_probe_update_all() must be called
//ust//		 * before the module containing tp_cb is unloaded.
//ust//		 */
//ust//		module_put(__module_text_address((unsigned long)elem->tp_cb));
//ust//	}
	elem->state__imv = 0;
	elem->single.func = __mark_empty_function;
	/* Update the function before setting the ptype */
	smp_wmb();
	elem->ptype = 0;	/* single probe */
	/*
	 * Leave the private data and channel_id/event_id there, because removal
	 * is racy and should be done only after an RCU period. These are never
	 * used until the next initialization anyway.
	 */
}

/**
 * marker_update_probe_range - Update a probe range
 * @begin: beginning of the range
 * @end: end of the range
 *
 * Updates the probe callback corresponding to a range of markers.
 */
void marker_update_probe_range(struct marker *begin,
	struct marker *end)
{
	struct marker *iter;
	struct marker_entry *mark_entry;

	mutex_lock(&markers_mutex);
	for (iter = begin; iter < end; iter++) {
		mark_entry = get_marker(iter->channel, iter->name);
		if (mark_entry) {
			set_marker(mark_entry, iter, !!mark_entry->refcount);
			/*
			 * ignore error, continue
			 */

			/* This is added for UST. We emit a core_marker_id event
			 * for markers that are already registered to a probe
			 * upon library load. Otherwise, no core_marker_id will
			 * be generated for these markers. Is this the right thing
			 * to do?
			 */
			trace_mark(metadata, core_marker_id,
				   "channel %s name %s event_id %hu "
				   "int #1u%zu long #1u%zu pointer #1u%zu "
				   "size_t #1u%zu alignment #1u%u",
				   iter->channel, iter->name, mark_entry->event_id,
				   sizeof(int), sizeof(long), sizeof(void *),
				   sizeof(size_t), ltt_get_alignment());
		} else {
			disable_marker(iter);
		}
	}
	mutex_unlock(&markers_mutex);
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
 * Site effect : marker_set_format may delete the marker entry (creating a
 * replacement).
 */
static void marker_update_probes(void)
{
	/* Core kernel markers */
//ust//	marker_update_probe_range(__start___markers, __stop___markers);
	/* Markers in modules. */
//ust//	module_update_markers();
	lib_update_markers();
//ust//	tracepoint_probe_update_all();
	/* Update immediate values */
	core_imv_update();
//ust//	module_imv_update(); /* FIXME: need to port for libs? */
	marker_update_processes();
}

/**
 * marker_probe_register -  Connect a probe to a marker
 * @channel: marker channel
 * @name: marker name
 * @format: format string
 * @probe: probe handler
 * @probe_private: probe private data
 *
 * private data must be a valid allocated memory address, or NULL.
 * Returns 0 if ok, error value on error.
 * The probe address must at least be aligned on the architecture pointer size.
 */
int marker_probe_register(const char *channel, const char *name,
			  const char *format, marker_probe_func *probe,
			  void *probe_private)
{
	struct marker_entry *entry;
	int ret = 0, ret_err;
	struct marker_probe_closure *old;
	int first_probe = 0;

	mutex_lock(&markers_mutex);
	entry = get_marker(channel, name);
	if (!entry) {
		first_probe = 1;
		entry = add_marker(channel, name, format);
		if (IS_ERR(entry))
			ret = PTR_ERR(entry);
		if (ret)
			goto end;
		ret = ltt_channels_register(channel);
		if (ret)
			goto error_remove_marker;
		ret = ltt_channels_get_index_from_name(channel);
		if (ret < 0)
			goto error_unregister_channel;
		entry->channel_id = ret;
		ret = ltt_channels_get_event_id(channel, name);
		if (ret < 0)
			goto error_unregister_channel;
		entry->event_id = ret;
		ret = 0;
		trace_mark(metadata, core_marker_id,
			   "channel %s name %s event_id %hu "
			   "int #1u%zu long #1u%zu pointer #1u%zu "
			   "size_t #1u%zu alignment #1u%u",
			   channel, name, entry->event_id,
			   sizeof(int), sizeof(long), sizeof(void *),
			   sizeof(size_t), ltt_get_alignment());
	} else if (format) {
		if (!entry->format)
			ret = marker_set_format(entry, format);
		else if (strcmp(entry->format, format))
			ret = -EPERM;
		if (ret)
			goto end;
	}

	/*
	 * If we detect that a call_rcu is pending for this marker,
	 * make sure it's executed now.
	 */
	if (entry->rcu_pending)
		rcu_barrier_sched();
	old = marker_entry_add_probe(entry, probe, probe_private);
	if (IS_ERR(old)) {
		ret = PTR_ERR(old);
		if (first_probe)
			goto error_unregister_channel;
		else
			goto end;
	}
	mutex_unlock(&markers_mutex);

	marker_update_probes();

	mutex_lock(&markers_mutex);
	entry = get_marker(channel, name);
	if (!entry)
		goto end;
	if (entry->rcu_pending)
		rcu_barrier_sched();
	entry->oldptr = old;
	entry->rcu_pending = 1;
	/* write rcu_pending before calling the RCU callback */
	smp_wmb();
	call_rcu_sched(&entry->rcu, free_old_closure);
	/*synchronize_rcu(); free_old_closure();*/
	goto end;

error_unregister_channel:
	ret_err = ltt_channels_unregister(channel);
	WARN_ON(ret_err);
error_remove_marker:
	ret_err = remove_marker(channel, name);
	WARN_ON(ret_err);
end:
	mutex_unlock(&markers_mutex);
	return ret;
}
//ust// EXPORT_SYMBOL_GPL(marker_probe_register);

/**
 * marker_probe_unregister -  Disconnect a probe from a marker
 * @channel: marker channel
 * @name: marker name
 * @probe: probe function pointer
 * @probe_private: probe private data
 *
 * Returns the private data given to marker_probe_register, or an ERR_PTR().
 * We do not need to call a synchronize_sched to make sure the probes have
 * finished running before doing a module unload, because the module unload
 * itself uses stop_machine(), which insures that every preempt disabled section
 * have finished.
 */
int marker_probe_unregister(const char *channel, const char *name,
			    marker_probe_func *probe, void *probe_private)
{
	struct marker_entry *entry;
	struct marker_probe_closure *old;
	int ret = -ENOENT;

	mutex_lock(&markers_mutex);
	entry = get_marker(channel, name);
	if (!entry)
		goto end;
	if (entry->rcu_pending)
		rcu_barrier_sched();
	old = marker_entry_remove_probe(entry, probe, probe_private);
	mutex_unlock(&markers_mutex);

	marker_update_probes();

	mutex_lock(&markers_mutex);
	entry = get_marker(channel, name);
	if (!entry)
		goto end;
	if (entry->rcu_pending)
		rcu_barrier_sched();
	entry->oldptr = old;
	entry->rcu_pending = 1;
	/* write rcu_pending before calling the RCU callback */
	smp_wmb();
	call_rcu_sched(&entry->rcu, free_old_closure);
	remove_marker(channel, name);	/* Ignore busy error message */
	ret = 0;
end:
	mutex_unlock(&markers_mutex);
	return ret;
}
//ust// EXPORT_SYMBOL_GPL(marker_probe_unregister);

static struct marker_entry *
get_marker_from_private_data(marker_probe_func *probe, void *probe_private)
{
	struct marker_entry *entry;
	unsigned int i;
	struct hlist_head *head;
	struct hlist_node *node;

	for (i = 0; i < MARKER_TABLE_SIZE; i++) {
		head = &marker_table[i];
		hlist_for_each_entry(entry, node, head, hlist) {
			if (!entry->ptype) {
				if (entry->single.func == probe
						&& entry->single.probe_private
						== probe_private)
					return entry;
			} else {
				struct marker_probe_closure *closure;
				closure = entry->multi;
				for (i = 0; closure[i].func; i++) {
					if (closure[i].func == probe &&
							closure[i].probe_private
							== probe_private)
						return entry;
				}
			}
		}
	}
	return NULL;
}

/**
 * marker_probe_unregister_private_data -  Disconnect a probe from a marker
 * @probe: probe function
 * @probe_private: probe private data
 *
 * Unregister a probe by providing the registered private data.
 * Only removes the first marker found in hash table.
 * Return 0 on success or error value.
 * We do not need to call a synchronize_sched to make sure the probes have
 * finished running before doing a module unload, because the module unload
 * itself uses stop_machine(), which insures that every preempt disabled section
 * have finished.
 */
int marker_probe_unregister_private_data(marker_probe_func *probe,
		void *probe_private)
{
	struct marker_entry *entry;
	int ret = 0;
	struct marker_probe_closure *old;
	const char *channel = NULL, *name = NULL;

	mutex_lock(&markers_mutex);
	entry = get_marker_from_private_data(probe, probe_private);
	if (!entry) {
		ret = -ENOENT;
		goto end;
	}
	if (entry->rcu_pending)
		rcu_barrier_sched();
	old = marker_entry_remove_probe(entry, NULL, probe_private);
	channel = kstrdup(entry->channel, GFP_KERNEL);
	name = kstrdup(entry->name, GFP_KERNEL);
	mutex_unlock(&markers_mutex);

	marker_update_probes();

	mutex_lock(&markers_mutex);
	entry = get_marker(channel, name);
	if (!entry)
		goto end;
	if (entry->rcu_pending)
		rcu_barrier_sched();
	entry->oldptr = old;
	entry->rcu_pending = 1;
	/* write rcu_pending before calling the RCU callback */
	smp_wmb();
	call_rcu_sched(&entry->rcu, free_old_closure);
	/* Ignore busy error message */
	remove_marker(channel, name);
end:
	mutex_unlock(&markers_mutex);
	kfree(channel);
	kfree(name);
	return ret;
}
//ust// EXPORT_SYMBOL_GPL(marker_probe_unregister_private_data);

/**
 * marker_get_private_data - Get a marker's probe private data
 * @channel: marker channel
 * @name: marker name
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
void *marker_get_private_data(const char *channel, const char *name,
			      marker_probe_func *probe, int num)
{
	struct hlist_head *head;
	struct hlist_node *node;
	struct marker_entry *e;
	size_t channel_len = strlen(channel) + 1;
	size_t name_len = strlen(name) + 1;
	int i;
	u32 hash;

	hash = jhash(channel, channel_len-1, 0) ^ jhash(name, name_len-1, 0);
	head = &marker_table[hash & ((1 << MARKER_HASH_BITS)-1)];
	hlist_for_each_entry(e, node, head, hlist) {
		if (!strcmp(channel, e->channel) && !strcmp(name, e->name)) {
			if (!e->ptype) {
				if (num == 0 && e->single.func == probe)
					return e->single.probe_private;
			} else {
				struct marker_probe_closure *closure;
				int match = 0;
				closure = e->multi;
				for (i = 0; closure[i].func; i++) {
					if (closure[i].func != probe)
						continue;
					if (match++ == num)
						return closure[i].probe_private;
				}
			}
			break;
		}
	}
	return ERR_PTR(-ENOENT);
}
//ust// EXPORT_SYMBOL_GPL(marker_get_private_data);

/**
 * markers_compact_event_ids - Compact markers event IDs and reassign channels
 *
 * Called when no channel users are active by the channel infrastructure.
 * Called with lock_markers() and channel mutex held.
 */
//ust// void markers_compact_event_ids(void)
//ust// {
//ust// 	struct marker_entry *entry;
//ust// 	unsigned int i;
//ust// 	struct hlist_head *head;
//ust// 	struct hlist_node *node;
//ust// 	int ret;
//ust// 
//ust// 	for (i = 0; i < MARKER_TABLE_SIZE; i++) {
//ust// 		head = &marker_table[i];
//ust// 		hlist_for_each_entry(entry, node, head, hlist) {
//ust// 			ret = ltt_channels_get_index_from_name(entry->channel);
//ust// 			WARN_ON(ret < 0);
//ust// 			entry->channel_id = ret;
//ust// 			ret = _ltt_channels_get_event_id(entry->channel,
//ust// 							 entry->name);
//ust// 			WARN_ON(ret < 0);
//ust// 			entry->event_id = ret;
//ust// 		}
//ust// 	}
//ust// }

//ust//#ifdef CONFIG_MODULES

/**
 * marker_get_iter_range - Get a next marker iterator given a range.
 * @marker: current markers (in), next marker (out)
 * @begin: beginning of the range
 * @end: end of the range
 *
 * Returns whether a next marker has been found (1) or not (0).
 * Will return the first marker in the range if the input marker is NULL.
 */
int marker_get_iter_range(struct marker **marker, struct marker *begin,
	struct marker *end)
{
	if (!*marker && begin != end) {
		*marker = begin;
		return 1;
	}
	if (*marker >= begin && *marker < end)
		return 1;
	return 0;
}
//ust// EXPORT_SYMBOL_GPL(marker_get_iter_range);

static void marker_get_iter(struct marker_iter *iter)
{
	int found = 0;

	/* Core kernel markers */
	if (!iter->lib) {
		/* ust FIXME: how come we cannot disable the following line? we shouldn't need core stuff */
		found = marker_get_iter_range(&iter->marker,
				__start___markers, __stop___markers);
		if (found)
			goto end;
	}
	/* Markers in modules. */
	found = lib_get_iter_markers(iter);
end:
	if (!found)
		marker_iter_reset(iter);
}

void marker_iter_start(struct marker_iter *iter)
{
	marker_get_iter(iter);
}
//ust// EXPORT_SYMBOL_GPL(marker_iter_start);

void marker_iter_next(struct marker_iter *iter)
{
	iter->marker++;
	/*
	 * iter->marker may be invalid because we blindly incremented it.
	 * Make sure it is valid by marshalling on the markers, getting the
	 * markers from following modules if necessary.
	 */
	marker_get_iter(iter);
}
//ust// EXPORT_SYMBOL_GPL(marker_iter_next);

void marker_iter_stop(struct marker_iter *iter)
{
}
//ust// EXPORT_SYMBOL_GPL(marker_iter_stop);

void marker_iter_reset(struct marker_iter *iter)
{
	iter->lib = NULL;
	iter->marker = NULL;
}
//ust// EXPORT_SYMBOL_GPL(marker_iter_reset);

#ifdef CONFIG_MARKERS_USERSPACE
/*
 * must be called with current->user_markers_mutex held
 */
static void free_user_marker(char __user *state, struct hlist_head *head)
{
	struct user_marker *umark;
	struct hlist_node *pos, *n;

	hlist_for_each_entry_safe(umark, pos, n, head, hlist) {
		if (umark->state == state) {
			hlist_del(&umark->hlist);
			kfree(umark);
		}
	}
}

//ust// asmlinkage long sys_marker(char __user *name, char __user *format,
//ust// 		char __user *state, int reg)
//ust// {
//ust// 	struct user_marker *umark;
//ust// 	long len;
//ust// 	struct marker_entry *entry;
//ust// 	int ret = 0;
//ust// 
//ust// 	printk(KERN_DEBUG "Program %s %s marker [%p, %p]\n",
//ust// 		current->comm, reg ? "registers" : "unregisters",
//ust// 		name, state);
//ust// 	if (reg) {
//ust// 		umark = kmalloc(sizeof(struct user_marker), GFP_KERNEL);
//ust// 		umark->name[MAX_USER_MARKER_NAME_LEN - 1] = '\0';
//ust// 		umark->format[MAX_USER_MARKER_FORMAT_LEN - 1] = '\0';
//ust// 		umark->state = state;
//ust// 		len = strncpy_from_user(umark->name, name,
//ust// 			MAX_USER_MARKER_NAME_LEN - 1);
//ust// 		if (len < 0) {
//ust// 			ret = -EFAULT;
//ust// 			goto error;
//ust// 		}
//ust// 		len = strncpy_from_user(umark->format, format,
//ust// 			MAX_USER_MARKER_FORMAT_LEN - 1);
//ust// 		if (len < 0) {
//ust// 			ret = -EFAULT;
//ust// 			goto error;
//ust// 		}
//ust// 		printk(KERN_DEBUG "Marker name : %s, format : %s", umark->name,
//ust// 			umark->format);
//ust// 		mutex_lock(&markers_mutex);
//ust// 		entry = get_marker("userspace", umark->name);
//ust// 		if (entry) {
//ust// 			if (entry->format &&
//ust// 				strcmp(entry->format, umark->format) != 0) {
//ust// 				printk(" error, wrong format in process %s",
//ust// 					current->comm);
//ust// 				ret = -EPERM;
//ust// 				goto error_unlock;
//ust// 			}
//ust// 			printk(" %s", !!entry->refcount
//ust// 					? "enabled" : "disabled");
//ust// 			if (put_user(!!entry->refcount, state)) {
//ust// 				ret = -EFAULT;
//ust// 				goto error_unlock;
//ust// 			}
//ust// 			printk("\n");
//ust// 		} else {
//ust// 			printk(" disabled\n");
//ust// 			if (put_user(0, umark->state)) {
//ust// 				printk(KERN_WARNING
//ust// 					"Marker in %s caused a fault\n",
//ust// 					current->comm);
//ust// 				goto error_unlock;
//ust// 			}
//ust// 		}
//ust// 		mutex_lock(&current->group_leader->user_markers_mutex);
//ust// 		hlist_add_head(&umark->hlist,
//ust// 			&current->group_leader->user_markers);
//ust// 		current->group_leader->user_markers_sequence++;
//ust// 		mutex_unlock(&current->group_leader->user_markers_mutex);
//ust// 		mutex_unlock(&markers_mutex);
//ust// 	} else {
//ust// 		mutex_lock(&current->group_leader->user_markers_mutex);
//ust// 		free_user_marker(state,
//ust// 			&current->group_leader->user_markers);
//ust// 		current->group_leader->user_markers_sequence++;
//ust// 		mutex_unlock(&current->group_leader->user_markers_mutex);
//ust// 	}
//ust// 	goto end;
//ust// error_unlock:
//ust// 	mutex_unlock(&markers_mutex);
//ust// error:
//ust// 	kfree(umark);
//ust// end:
//ust// 	return ret;
//ust// }
//ust// 
//ust// /*
//ust//  * Types :
//ust//  * string : 0
//ust//  */
//ust// asmlinkage long sys_trace(int type, uint16_t id,
//ust// 		char __user *ubuf)
//ust// {
//ust// 	long ret = -EPERM;
//ust// 	char *page;
//ust// 	int len;
//ust// 
//ust// 	switch (type) {
//ust// 	case 0:	/* String */
//ust// 		ret = -ENOMEM;
//ust// 		page = (char *)__get_free_page(GFP_TEMPORARY);
//ust// 		if (!page)
//ust// 			goto string_out;
//ust// 		len = strncpy_from_user(page, ubuf, PAGE_SIZE);
//ust// 		if (len < 0) {
//ust// 			ret = -EFAULT;
//ust// 			goto string_err;
//ust// 		}
//ust// 		trace_mark(userspace, string, "string %s", page);
//ust// string_err:
//ust// 		free_page((unsigned long) page);
//ust// string_out:
//ust// 		break;
//ust// 	default:
//ust// 		break;
//ust// 	}
//ust// 	return ret;
//ust// }

//ust// static void marker_update_processes(void)
//ust// {
//ust// 	struct task_struct *g, *t;
//ust// 
//ust// 	/*
//ust// 	 * markers_mutex is taken to protect the p->user_markers read.
//ust// 	 */
//ust// 	mutex_lock(&markers_mutex);
//ust// 	read_lock(&tasklist_lock);
//ust// 	for_each_process(g) {
//ust// 		WARN_ON(!thread_group_leader(g));
//ust// 		if (hlist_empty(&g->user_markers))
//ust// 			continue;
//ust// 		if (strcmp(g->comm, "testprog") == 0)
//ust// 			printk(KERN_DEBUG "set update pending for testprog\n");
//ust// 		t = g;
//ust// 		do {
//ust// 			/* TODO : implement this thread flag in each arch. */
//ust// 			set_tsk_thread_flag(t, TIF_MARKER_PENDING);
//ust// 		} while ((t = next_thread(t)) != g);
//ust// 	}
//ust// 	read_unlock(&tasklist_lock);
//ust// 	mutex_unlock(&markers_mutex);
//ust// }

/*
 * Update current process.
 * Note that we have to wait a whole scheduler period before we are sure that
 * every running userspace threads have their markers updated.
 * (synchronize_sched() can be used to insure this).
 */
void marker_update_process(void)
{
	struct user_marker *umark;
	struct hlist_node *pos;
	struct marker_entry *entry;

	mutex_lock(&markers_mutex);
	mutex_lock(&current->group_leader->user_markers_mutex);
	if (strcmp(current->comm, "testprog") == 0)
		printk(KERN_DEBUG "do update pending for testprog\n");
	hlist_for_each_entry(umark, pos,
			&current->group_leader->user_markers, hlist) {
		printk(KERN_DEBUG "Updating marker %s in %s\n",
			umark->name, current->comm);
		entry = get_marker("userspace", umark->name);
		if (entry) {
			if (entry->format &&
				strcmp(entry->format, umark->format) != 0) {
				printk(KERN_WARNING
					" error, wrong format in process %s\n",
					current->comm);
				break;
			}
			if (put_user(!!entry->refcount, umark->state)) {
				printk(KERN_WARNING
					"Marker in %s caused a fault\n",
					current->comm);
				break;
			}
		} else {
			if (put_user(0, umark->state)) {
				printk(KERN_WARNING
					"Marker in %s caused a fault\n",
					current->comm);
				break;
			}
		}
	}
	clear_thread_flag(TIF_MARKER_PENDING);
	mutex_unlock(&current->group_leader->user_markers_mutex);
	mutex_unlock(&markers_mutex);
}

/*
 * Called at process exit and upon do_execve().
 * We assume that when the leader exits, no more references can be done to the
 * leader structure by the other threads.
 */
void exit_user_markers(struct task_struct *p)
{
	struct user_marker *umark;
	struct hlist_node *pos, *n;

	if (thread_group_leader(p)) {
		mutex_lock(&markers_mutex);
		mutex_lock(&p->user_markers_mutex);
		hlist_for_each_entry_safe(umark, pos, n, &p->user_markers,
			hlist)
		    kfree(umark);
		INIT_HLIST_HEAD(&p->user_markers);
		p->user_markers_sequence++;
		mutex_unlock(&p->user_markers_mutex);
		mutex_unlock(&markers_mutex);
	}
}

int is_marker_enabled(const char *channel, const char *name)
{
	struct marker_entry *entry;

	mutex_lock(&markers_mutex);
	entry = get_marker(channel, name);
	mutex_unlock(&markers_mutex);

	return entry && !!entry->refcount;
}
//ust// #endif

int marker_module_notify(struct notifier_block *self,
			 unsigned long val, void *data)
{
	struct module *mod = data;

	switch (val) {
	case MODULE_STATE_COMING:
		marker_update_probe_range(mod->markers,
			mod->markers + mod->num_markers);
		break;
	case MODULE_STATE_GOING:
		marker_update_probe_range(mod->markers,
			mod->markers + mod->num_markers);
		break;
	}
	return 0;
}

struct notifier_block marker_module_nb = {
	.notifier_call = marker_module_notify,
	.priority = 0,
};

//ust// static int init_markers(void)
//ust// {
//ust// 	return register_module_notifier(&marker_module_nb);
//ust// }
//ust// __initcall(init_markers);
/* TODO: call marker_module_nb() when a library is linked at runtime (dlopen)? */

#endif /* CONFIG_MODULES */

void ltt_dump_marker_state(struct ltt_trace_struct *trace)
{
	struct marker_iter iter;
	struct ltt_probe_private_data call_data;
	const char *channel;

	call_data.trace = trace;
	call_data.serializer = NULL;

	marker_iter_reset(&iter);
	marker_iter_start(&iter);
	for (; iter.marker != NULL; marker_iter_next(&iter)) {
		if (!_imv_read(iter.marker->state))
			continue;
		channel = ltt_channels_get_name_from_index(
				iter.marker->channel_id);
		__trace_mark(0, metadata, core_marker_id,
			&call_data,
			"channel %s name %s event_id %hu "
			"int #1u%zu long #1u%zu pointer #1u%zu "
			"size_t #1u%zu alignment #1u%u",
			channel,
			iter.marker->name,
			iter.marker->event_id,
			sizeof(int), sizeof(long),
			sizeof(void *), sizeof(size_t),
			ltt_get_alignment());
		if (iter.marker->format)
			__trace_mark(0, metadata,
				core_marker_format,
				&call_data,
				"channel %s name %s format %s",
				channel,
				iter.marker->name,
				iter.marker->format);
	}
	marker_iter_stop(&iter);
}
//ust// EXPORT_SYMBOL_GPL(ltt_dump_marker_state);


static LIST_HEAD(libs);

/*
 * Returns 0 if current not found.
 * Returns 1 if current found.
 */
int lib_get_iter_markers(struct marker_iter *iter)
{
	struct lib *iter_lib;
	int found = 0;

//ust//	mutex_lock(&module_mutex);
	list_for_each_entry(iter_lib, &libs, list) {
		if (iter_lib < iter->lib)
			continue;
		else if (iter_lib > iter->lib)
			iter->marker = NULL;
		found = marker_get_iter_range(&iter->marker,
			iter_lib->markers_start,
			iter_lib->markers_start + iter_lib->markers_count);
		if (found) {
			iter->lib = iter_lib;
			break;
		}
	}
//ust//	mutex_unlock(&module_mutex);
	return found;
}

void lib_update_markers(void)
{
	struct lib *lib;

//ust//	mutex_lock(&module_mutex);
	list_for_each_entry(lib, &libs, list)
		marker_update_probe_range(lib->markers_start,
				lib->markers_start + lib->markers_count);
//ust//	mutex_unlock(&module_mutex);
}

static void (*new_marker_cb)(struct marker *) = NULL;

void marker_set_new_marker_cb(void (*cb)(struct marker *))
{
	new_marker_cb = cb;
}

static void new_markers(struct marker *start, struct marker *end)
{
	if(new_marker_cb) {
		struct marker *m;
		for(m=start; m < end; m++) {
			new_marker_cb(m);
		}
	}
}

int marker_register_lib(struct marker *markers_start, int markers_count)
{
	struct lib *pl;

	pl = (struct lib *) malloc(sizeof(struct lib));

	pl->markers_start = markers_start;
	pl->markers_count = markers_count;

	/* FIXME: maybe protect this with its own mutex? */
	lock_markers();
	list_add(&pl->list, &libs);
	unlock_markers();

	new_markers(markers_start, markers_start + markers_count);

	/* FIXME: update just the loaded lib */
	lib_update_markers();

	DBG("just registered a markers section from %p and having %d markers", markers_start, markers_count);
	
	return 0;
}

int marker_unregister_lib(struct marker *markers_start, int markers_count)
{
	/*FIXME: implement; but before implementing, marker_register_lib must
          have appropriate locking. */

	return 0;
}

static int initialized = 0;

void __attribute__((constructor)) init_markers(void)
{
	if(!initialized) {
		marker_register_lib(__start___markers, (((long)__stop___markers)-((long)__start___markers))/sizeof(struct marker));
		printf("markers_start: %p, markers_stop: %p\n", __start___markers, __stop___markers);
		initialized = 1;
	}
}
