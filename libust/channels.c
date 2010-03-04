/*
 * ltt/ltt-channels.c
 *
 * (C) Copyright 2008 - Mathieu Desnoyers (mathieu.desnoyers@polymtl.ca)
 *
 * LTTng channel management.
 *
 * Author:
 *	Mathieu Desnoyers (mathieu.desnoyers@polymtl.ca)
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

//ust// #include <linux/module.h>
//ust// #include <linux/ltt-channels.h>
//ust// #include <linux/mutex.h>
//ust// #include <linux/vmalloc.h>

#include <ust/kernelcompat.h>
#include "channels.h"
#include "usterr.h"
#include <ust/marker.h>

/*
 * ltt_channel_mutex may be nested inside the LTT trace mutex.
 * ltt_channel_mutex mutex may be nested inside markers mutex.
 */
static DEFINE_MUTEX(ltt_channel_mutex);
static LIST_HEAD(ltt_channels);
/*
 * Index of next channel in array. Makes sure that as long as a trace channel is
 * allocated, no array index will be re-used when a channel is freed and then
 * another channel is allocated. This index is cleared and the array indexeds
 * get reassigned when the index_kref goes back to 0, which indicates that no
 * more trace channels are allocated.
 */
static unsigned int free_index;
static struct kref index_kref;	/* Keeps track of allocated trace channels */

static struct ltt_channel_setting *lookup_channel(const char *name)
{
	struct ltt_channel_setting *iter;

	list_for_each_entry(iter, &ltt_channels, list)
		if (strcmp(name, iter->name) == 0)
			return iter;
	return NULL;
}

/*
 * Must be called when channel refcount falls to 0 _and_ also when the last
 * trace is freed. This function is responsible for compacting the channel and
 * event IDs when no users are active.
 *
 * Called with lock_markers() and channels mutex held.
 */
static void release_channel_setting(struct kref *kref)
{
	struct ltt_channel_setting *setting = container_of(kref,
		struct ltt_channel_setting, kref);
	struct ltt_channel_setting *iter;

	if (uatomic_read(&index_kref.refcount) == 0
	    && uatomic_read(&setting->kref.refcount) == 0) {
		list_del(&setting->list);
		kfree(setting);

		free_index = 0;
		list_for_each_entry(iter, &ltt_channels, list) {
			iter->index = free_index++;
			iter->free_event_id = 0;
		}
//ust//		markers_compact_event_ids();
	}
}

/*
 * Perform channel index compaction when the last trace channel is freed.
 *
 * Called with lock_markers() and channels mutex held.
 */
static void release_trace_channel(struct kref *kref)
{
	struct ltt_channel_setting *iter, *n;

	list_for_each_entry_safe(iter, n, &ltt_channels, list)
		release_channel_setting(&iter->kref);
}

/**
 * ltt_channels_register - Register a trace channel.
 * @name: channel name
 *
 * Uses refcounting.
 */
int ltt_channels_register(const char *name)
{
	struct ltt_channel_setting *setting;
	int ret = 0;

	mutex_lock(&ltt_channel_mutex);
	setting = lookup_channel(name);
	if (setting) {
		if (uatomic_read(&setting->kref.refcount) == 0)
			goto init_kref;
		else {
			kref_get(&setting->kref);
			goto end;
		}
	}
	setting = kzalloc(sizeof(*setting), GFP_KERNEL);
	if (!setting) {
		ret = -ENOMEM;
		goto end;
	}
	list_add(&setting->list, &ltt_channels);
	strncpy(setting->name, name, PATH_MAX-1);
	setting->index = free_index++;
init_kref:
	kref_init(&setting->kref);
end:
	mutex_unlock(&ltt_channel_mutex);
	return ret;
}
//ust// EXPORT_SYMBOL_GPL(ltt_channels_register);

/**
 * ltt_channels_unregister - Unregister a trace channel.
 * @name: channel name
 *
 * Must be called with markers mutex held.
 */
int ltt_channels_unregister(const char *name)
{
	struct ltt_channel_setting *setting;
	int ret = 0;

	mutex_lock(&ltt_channel_mutex);
	setting = lookup_channel(name);
	if (!setting || uatomic_read(&setting->kref.refcount) == 0) {
		ret = -ENOENT;
		goto end;
	}
	kref_put(&setting->kref, release_channel_setting);
end:
	mutex_unlock(&ltt_channel_mutex);
	return ret;
}
//ust// EXPORT_SYMBOL_GPL(ltt_channels_unregister);

/**
 * ltt_channels_set_default - Set channel default behavior.
 * @name: default channel name
 * @subbuf_size: size of the subbuffers
 * @subbuf_cnt: number of subbuffers
 */
int ltt_channels_set_default(const char *name,
			     unsigned int subbuf_size,
			     unsigned int subbuf_cnt)
{
	struct ltt_channel_setting *setting;
	int ret = 0;

	mutex_lock(&ltt_channel_mutex);
	setting = lookup_channel(name);
	if (!setting || uatomic_read(&setting->kref.refcount) == 0) {
		ret = -ENOENT;
		goto end;
	}
	setting->subbuf_size = subbuf_size;
	setting->subbuf_cnt = subbuf_cnt;
end:
	mutex_unlock(&ltt_channel_mutex);
	return ret;
}
//ust// EXPORT_SYMBOL_GPL(ltt_channels_set_default);

/**
 * ltt_channels_get_name_from_index - get channel name from channel index
 * @index: channel index
 *
 * Allows to lookup the channel name given its index. Done to keep the name
 * information outside of each trace channel instance.
 */
const char *ltt_channels_get_name_from_index(unsigned int index)
{
	struct ltt_channel_setting *iter;

	list_for_each_entry(iter, &ltt_channels, list)
		if (iter->index == index && uatomic_read(&iter->kref.refcount))
			return iter->name;
	return NULL;
}
//ust// EXPORT_SYMBOL_GPL(ltt_channels_get_name_from_index);

static struct ltt_channel_setting *
ltt_channels_get_setting_from_name(const char *name)
{
	struct ltt_channel_setting *iter;

	list_for_each_entry(iter, &ltt_channels, list)
		if (!strcmp(iter->name, name)
		    && uatomic_read(&iter->kref.refcount))
			return iter;
	return NULL;
}

/**
 * ltt_channels_get_index_from_name - get channel index from channel name
 * @name: channel name
 *
 * Allows to lookup the channel index given its name. Done to keep the name
 * information outside of each trace channel instance.
 * Returns -1 if not found.
 */
int ltt_channels_get_index_from_name(const char *name)
{
	struct ltt_channel_setting *setting;

	setting = ltt_channels_get_setting_from_name(name);
	if (setting)
		return setting->index;
	else
		return -1;
}
//ust// EXPORT_SYMBOL_GPL(ltt_channels_get_index_from_name);

/**
 * ltt_channels_trace_alloc - Allocate channel structures for a trace
 * @subbuf_size: subbuffer size. 0 uses default.
 * @subbuf_cnt: number of subbuffers per per-cpu buffers. 0 uses default.
 * @flags: Default channel flags
 *
 * Use the current channel list to allocate the channels for a trace.
 * Called with trace lock held. Does not perform the trace buffer allocation,
 * because we must let the user overwrite specific channel sizes.
 */
struct ust_channel *ltt_channels_trace_alloc(unsigned int *nr_channels,
						    int overwrite,
						    int active)
{
	struct ust_channel *channel = NULL;
	struct ltt_channel_setting *iter;

	mutex_lock(&ltt_channel_mutex);
	if (!free_index) {
		WARN("ltt_channels_trace_alloc: no free_index; are there any probes connected?");
		goto end;
	}
	if (!uatomic_read(&index_kref.refcount))
		kref_init(&index_kref);
	else
		kref_get(&index_kref);
	*nr_channels = free_index;
	channel = kzalloc(sizeof(struct ust_channel) * free_index,
			  GFP_KERNEL);
	if (!channel) {
		WARN("ltt_channel_struct: channel null after alloc");
		goto end;
	}
	list_for_each_entry(iter, &ltt_channels, list) {
		if (!uatomic_read(&iter->kref.refcount))
			continue;
		channel[iter->index].subbuf_size = iter->subbuf_size;
		channel[iter->index].subbuf_cnt = iter->subbuf_cnt;
		channel[iter->index].overwrite = overwrite;
		channel[iter->index].active = active;
		channel[iter->index].channel_name = iter->name;
	}
end:
	mutex_unlock(&ltt_channel_mutex);
	return channel;
}
//ust// EXPORT_SYMBOL_GPL(ltt_channels_trace_alloc);

/**
 * ltt_channels_trace_free - Free one trace's channels
 * @channels: channels to free
 *
 * Called with trace lock held. The actual channel buffers must be freed before
 * this function is called.
 */
void ltt_channels_trace_free(struct ust_channel *channels)
{
	lock_markers();
	mutex_lock(&ltt_channel_mutex);
	kfree(channels);
	kref_put(&index_kref, release_trace_channel);
	mutex_unlock(&ltt_channel_mutex);
	unlock_markers();
}
//ust// EXPORT_SYMBOL_GPL(ltt_channels_trace_free);

/**
 * _ltt_channels_get_event_id - get next event ID for a marker
 * @channel: channel name
 * @name: event name
 *
 * Returns a unique event ID (for this channel) or < 0 on error.
 * Must be called with channels mutex held.
 */
int _ltt_channels_get_event_id(const char *channel, const char *name)
{
	struct ltt_channel_setting *setting;
	int ret;

	setting = ltt_channels_get_setting_from_name(channel);
	if (!setting) {
		ret = -ENOENT;
		goto end;
	}
	if (strcmp(channel, "metadata") == 0) {
		if (strcmp(name, "core_marker_id") == 0)
			ret = 0;
		else if (strcmp(name, "core_marker_format") == 0)
			ret = 1;
		else if (strcmp(name, "testev") == 0)
			ret = 2;
		else
			ret = -ENOENT;
		goto end;
	}
	if (setting->free_event_id == EVENTS_PER_CHANNEL - 1) {
		ret = -ENOSPC;
		goto end;
	}
	ret = setting->free_event_id++;
end:
	return ret;
}

/**
 * ltt_channels_get_event_id - get next event ID for a marker
 * @channel: channel name
 * @name: event name
 *
 * Returns a unique event ID (for this channel) or < 0 on error.
 */
int ltt_channels_get_event_id(const char *channel, const char *name)
{
	int ret;

	mutex_lock(&ltt_channel_mutex);
	ret = _ltt_channels_get_event_id(channel, name);
	mutex_unlock(&ltt_channel_mutex);
	return ret;
}

//ust// MODULE_LICENSE("GPL");
//ust// MODULE_AUTHOR("Mathieu Desnoyers");
//ust// MODULE_DESCRIPTION("Linux Trace Toolkit Next Generation Channel Management");
