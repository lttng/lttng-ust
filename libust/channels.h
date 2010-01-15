#ifndef UST_CHANNELS_H
#define UST_CHANNELS_H

/*
 * Copyright (C) 2008 Mathieu Desnoyers (mathieu.desnoyers@polymtl.ca)
 *
 * Dynamic tracer channel allocation.
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

#include <linux/limits.h>
#include <errno.h>

#include <ust/kernelcompat.h>
#include <kcompat/kref.h>

#define EVENTS_PER_CHANNEL	65536

struct ltt_trace_struct;

struct ust_buffer;

struct ust_channel {
	/* First 32 bytes cache-hot cacheline */
	struct ltt_trace_struct	*trace;
	void *buf;
	int overwrite:1;
	int active:1;
	unsigned int n_subbufs_order;
	unsigned long commit_count_mask;	/*
						 * Commit count mask, removing
						 * the MSBs corresponding to
						 * bits used to represent the
						 * subbuffer index.
						 */
	/* End of first 32 bytes cacheline */

	/*
	 * buffer_begin - called on buffer-switch to a new sub-buffer
	 * @buf: the channel buffer containing the new sub-buffer
	 */
	void (*buffer_begin) (struct ust_buffer *buf,
			u64 tsc, unsigned int subbuf_idx);
	/*
	 * buffer_end - called on buffer-switch to a new sub-buffer
	 * @buf: the channel buffer containing the previous sub-buffer
	 */
	void (*buffer_end) (struct ust_buffer *buf,
			u64 tsc, unsigned int offset, unsigned int subbuf_idx);
	struct kref kref;	/* Channel transport reference count */
	size_t subbuf_size;
	int subbuf_size_order;
	unsigned int subbuf_cnt;
	const char *channel_name;

	int buf_shmid;

	u32 version;
	size_t alloc_size;
	struct list_head list;
} ____cacheline_aligned;

struct ltt_channel_setting {
	unsigned int subbuf_size;
	unsigned int subbuf_cnt;
	struct kref kref;	/* Number of references to structure content */
	struct list_head list;
	unsigned int index;	/* index of channel in trace channel array */
	u16 free_event_id;	/* Next event ID to allocate */
	char name[PATH_MAX];
};

extern int ltt_channels_register(const char *name);
extern int ltt_channels_unregister(const char *name);
extern int ltt_channels_set_default(const char *name,
			     unsigned int subbuf_size,
			     unsigned int subbuf_cnt);
extern const char *ltt_channels_get_name_from_index(unsigned int index);
extern int ltt_channels_get_index_from_name(const char *name);
extern struct ust_channel *ltt_channels_trace_alloc(unsigned int *nr_channels,
						    int overwrite,
						    int active);
extern void ltt_channels_trace_free(struct ust_channel *channels);
extern int _ltt_channels_get_event_id(const char *channel, const char *name);
extern int ltt_channels_get_event_id(const char *channel, const char *name);

#endif /* UST_CHANNELS_H */
