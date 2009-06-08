/*
 * Public API and common code for kernel->userspace relay file support.
 *
 * Copyright (C) 2002-2005 - Tom Zanussi (zanussi@us.ibm.com), IBM Corp
 * Copyright (C) 1999-2005 - Karim Yaghmour (karim@opersys.com)
 * Copyright (C) 2008 - Mathieu Desnoyers (mathieu.desnoyers@polymtl.ca)
 *
 * Moved to kernel/relay.c by Paul Mundt, 2006.
 * November 2006 - CPU hotplug support by Mathieu Desnoyers
 * 	(mathieu.desnoyers@polymtl.ca)
 *
 * This file is released under the GPL.
 */
//ust// #include <linux/errno.h>
//ust// #include <linux/stddef.h>
//ust// #include <linux/slab.h>
//ust// #include <linux/module.h>
//ust// #include <linux/string.h>
//ust// #include <linux/ltt-relay.h>
//ust// #include <linux/vmalloc.h>
//ust// #include <linux/mm.h>
//ust// #include <linux/cpu.h>
//ust// #include <linux/splice.h>
//ust// #include <linux/bitops.h>
#include "kernelcompat.h"
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/shm.h>
//#include "list.h"
#include "relay.h"
#include "channels.h"
#include "kref.h"
#include "tracer.h"
#include "tracercore.h"
#include "usterr.h"

/* list of open channels, for cpu hotplug */
static DEFINE_MUTEX(relay_channels_mutex);
static LIST_HEAD(relay_channels);


static struct dentry *ltt_create_buf_file_callback(struct rchan_buf *buf);

/**
 *	relay_alloc_buf - allocate a channel buffer
 *	@buf: the buffer struct
 *	@size: total size of the buffer
 */
//ust// static int relay_alloc_buf(struct rchan_buf *buf, size_t *size)
//ust//{
//ust//	unsigned int i, n_pages;
//ust//	struct buf_page *buf_page, *n;
//ust//
//ust//	*size = PAGE_ALIGN(*size);
//ust//	n_pages = *size >> PAGE_SHIFT;
//ust//
//ust//	INIT_LIST_HEAD(&buf->pages);
//ust//
//ust//	for (i = 0; i < n_pages; i++) {
//ust//		buf_page = kmalloc_node(sizeof(*buf_page), GFP_KERNEL,
//ust//			cpu_to_node(buf->cpu));
//ust//		if (unlikely(!buf_page))
//ust//			goto depopulate;
//ust//		buf_page->page = alloc_pages_node(cpu_to_node(buf->cpu),
//ust//			GFP_KERNEL | __GFP_ZERO, 0);
//ust//		if (unlikely(!buf_page->page)) {
//ust//			kfree(buf_page);
//ust//			goto depopulate;
//ust//		}
//ust//		list_add_tail(&buf_page->list, &buf->pages);
//ust//		buf_page->offset = (size_t)i << PAGE_SHIFT;
//ust//		buf_page->buf = buf;
//ust//		set_page_private(buf_page->page, (unsigned long)buf_page);
//ust//		if (i == 0) {
//ust//			buf->wpage = buf_page;
//ust//			buf->hpage[0] = buf_page;
//ust//			buf->hpage[1] = buf_page;
//ust//			buf->rpage = buf_page;
//ust//		}
//ust//	}
//ust//	buf->page_count = n_pages;
//ust//	return 0;
//ust//
//ust//depopulate:
//ust//	list_for_each_entry_safe(buf_page, n, &buf->pages, list) {
//ust//		list_del_init(&buf_page->list);
//ust//		__free_page(buf_page->page);
//ust//		kfree(buf_page);
//ust//	}
//ust//	return -ENOMEM;
//ust//}

static int relay_alloc_buf(struct rchan_buf *buf, size_t *size)
{
//ust//	unsigned int n_pages;
//ust//	struct buf_page *buf_page, *n;

	void *ptr;
	int result;

	*size = PAGE_ALIGN(*size);

	result = buf->shmid = shmget(getpid(), *size, IPC_CREAT | IPC_EXCL | 0700);
	if(buf->shmid == -1) {
		PERROR("shmget");
		return -1;
	}

	ptr = shmat(buf->shmid, NULL, 0);
	if(ptr == (void *) -1) {
		perror("shmat");
		goto destroy_shmem;
	}

	/* Already mark the shared memory for destruction. This will occur only
         * when all users have detached.
	 */
	result = shmctl(buf->shmid, IPC_RMID, NULL);
	if(result == -1) {
		perror("shmctl");
		return -1;
	}

	buf->buf_data = ptr;
	buf->buf_size = *size;

	return 0;

	destroy_shmem:
	result = shmctl(buf->shmid, IPC_RMID, NULL);
	if(result == -1) {
		perror("shmctl");
	}

	return -1;
}

/**
 *	relay_create_buf - allocate and initialize a channel buffer
 *	@chan: the relay channel
 *	@cpu: cpu the buffer belongs to
 *
 *	Returns channel buffer if successful, %NULL otherwise.
 */
static struct rchan_buf *relay_create_buf(struct rchan *chan)
{
	int ret;
	struct rchan_buf *buf = kzalloc(sizeof(struct rchan_buf), GFP_KERNEL);
	if (!buf)
		return NULL;

//	buf->cpu = cpu;
	ret = relay_alloc_buf(buf, &chan->alloc_size);
	if (ret)
		goto free_buf;

	buf->chan = chan;
	kref_get(&buf->chan->kref);
	return buf;

free_buf:
	kfree(buf);
	return NULL;
}

/**
 *	relay_destroy_channel - free the channel struct
 *	@kref: target kernel reference that contains the relay channel
 *
 *	Should only be called from kref_put().
 */
static void relay_destroy_channel(struct kref *kref)
{
	struct rchan *chan = container_of(kref, struct rchan, kref);
	kfree(chan);
}

/**
 *	relay_destroy_buf - destroy an rchan_buf struct and associated buffer
 *	@buf: the buffer struct
 */
static void relay_destroy_buf(struct rchan_buf *buf)
{
	struct rchan *chan = buf->chan;
	struct buf_page *buf_page, *n;
	int result;

	result = munmap(buf->buf_data, buf->buf_size);
	if(result == -1) {
		PERROR("munmap");
	}

//ust//	chan->buf[buf->cpu] = NULL;
	kfree(buf);
	kref_put(&chan->kref, relay_destroy_channel);
}

/**
 *	relay_remove_buf - remove a channel buffer
 *	@kref: target kernel reference that contains the relay buffer
 *
 *	Removes the file from the fileystem, which also frees the
 *	rchan_buf_struct and the channel buffer.  Should only be called from
 *	kref_put().
 */
static void relay_remove_buf(struct kref *kref)
{
	struct rchan_buf *buf = container_of(kref, struct rchan_buf, kref);
//ust//	buf->chan->cb->remove_buf_file(buf);
	relay_destroy_buf(buf);
}

/*
 * High-level relay kernel API and associated functions.
 */

/*
 * rchan_callback implementations defining default channel behavior.  Used
 * in place of corresponding NULL values in client callback struct.
 */

/*
 * create_buf_file_create() default callback.  Does nothing.
 */
static struct dentry *create_buf_file_default_callback(const char *filename,
						       struct dentry *parent,
						       int mode,
						       struct rchan_buf *buf)
{
	return NULL;
}

/*
 * remove_buf_file() default callback.  Does nothing.
 */
static int remove_buf_file_default_callback(struct dentry *dentry)
{
	return -EINVAL;
}

/**
 *	wakeup_readers - wake up readers waiting on a channel
 *	@data: contains the channel buffer
 *
 *	This is the timer function used to defer reader waking.
 */
//ust// static void wakeup_readers(unsigned long data)
//ust// {
//ust// 	struct rchan_buf *buf = (struct rchan_buf *)data;
//ust// 	wake_up_interruptible(&buf->read_wait);
//ust// }

/**
 *	__relay_reset - reset a channel buffer
 *	@buf: the channel buffer
 *	@init: 1 if this is a first-time initialization
 *
 *	See relay_reset() for description of effect.
 */
static void __relay_reset(struct rchan_buf *buf, unsigned int init)
{
	if (init) {
//ust//		init_waitqueue_head(&buf->read_wait);
		kref_init(&buf->kref);
//ust//		setup_timer(&buf->timer, wakeup_readers, (unsigned long)buf);
	} else
//ust//		del_timer_sync(&buf->timer);

	buf->finalized = 0;
}

/*
 *	relay_open_buf - create a new relay channel buffer
 *
 *	used by relay_open() and CPU hotplug.
 */
static struct rchan_buf *relay_open_buf(struct rchan *chan)
{
	struct rchan_buf *buf = NULL;
	struct dentry *dentry;
//ust//	char *tmpname;

//ust//	tmpname = kzalloc(NAME_MAX + 1, GFP_KERNEL);
//ust//	if (!tmpname)
//ust//		goto end;
//ust//	snprintf(tmpname, NAME_MAX, "%s%d", chan->base_filename, cpu);

	buf = relay_create_buf(chan);
	if (!buf)
		goto free_name;

	__relay_reset(buf, 1);

	/* Create file in fs */
//ust//	dentry = chan->cb->create_buf_file(tmpname, chan->parent, S_IRUSR,
//ust//					   buf);

	ltt_create_buf_file_callback(buf); // ust //

//ust//	if (!dentry)
//ust//		goto free_buf;
//ust//
//ust//	buf->dentry = dentry;

	goto free_name;

free_buf:
	relay_destroy_buf(buf);
	buf = NULL;
free_name:
//ust//	kfree(tmpname);
end:
	return buf;
}

/**
 *	relay_close_buf - close a channel buffer
 *	@buf: channel buffer
 *
 *	Marks the buffer finalized and restores the default callbacks.
 *	The channel buffer and channel buffer data structure are then freed
 *	automatically when the last reference is given up.
 */
static void relay_close_buf(struct rchan_buf *buf)
{
//ust//	del_timer_sync(&buf->timer);
	kref_put(&buf->kref, relay_remove_buf);
}

//ust// static void setup_callbacks(struct rchan *chan,
//ust// 				   struct rchan_callbacks *cb)
//ust// {
//ust// 	if (!cb) {
//ust// 		chan->cb = &default_channel_callbacks;
//ust// 		return;
//ust// 	}
//ust// 
//ust// 	if (!cb->create_buf_file)
//ust// 		cb->create_buf_file = create_buf_file_default_callback;
//ust// 	if (!cb->remove_buf_file)
//ust// 		cb->remove_buf_file = remove_buf_file_default_callback;
//ust// 	chan->cb = cb;
//ust// }

/**
 * 	relay_hotcpu_callback - CPU hotplug callback
 * 	@nb: notifier block
 * 	@action: hotplug action to take
 * 	@hcpu: CPU number
 *
 * 	Returns the success/failure of the operation. (%NOTIFY_OK, %NOTIFY_BAD)
 */
//ust// static int __cpuinit relay_hotcpu_callback(struct notifier_block *nb,
//ust// 				unsigned long action,
//ust// 				void *hcpu)
//ust// {
//ust// 	unsigned int hotcpu = (unsigned long)hcpu;
//ust// 	struct rchan *chan;
//ust// 
//ust// 	switch (action) {
//ust// 	case CPU_UP_PREPARE:
//ust// 	case CPU_UP_PREPARE_FROZEN:
//ust// 		mutex_lock(&relay_channels_mutex);
//ust// 		list_for_each_entry(chan, &relay_channels, list) {
//ust// 			if (chan->buf[hotcpu])
//ust// 				continue;
//ust// 			chan->buf[hotcpu] = relay_open_buf(chan, hotcpu);
//ust// 			if (!chan->buf[hotcpu]) {
//ust// 				printk(KERN_ERR
//ust// 					"relay_hotcpu_callback: cpu %d buffer "
//ust// 					"creation failed\n", hotcpu);
//ust// 				mutex_unlock(&relay_channels_mutex);
//ust// 				return NOTIFY_BAD;
//ust// 			}
//ust// 		}
//ust// 		mutex_unlock(&relay_channels_mutex);
//ust// 		break;
//ust// 	case CPU_DEAD:
//ust// 	case CPU_DEAD_FROZEN:
//ust// 		/* No need to flush the cpu : will be flushed upon
//ust// 		 * final relay_flush() call. */
//ust// 		break;
//ust// 	}
//ust// 	return NOTIFY_OK;
//ust// }

/**
 *	ltt_relay_open - create a new relay channel
 *	@base_filename: base name of files to create
 *	@parent: dentry of parent directory, %NULL for root directory
 *	@subbuf_size: size of sub-buffers
 *	@n_subbufs: number of sub-buffers
 *	@cb: client callback functions
 *	@private_data: user-defined data
 *
 *	Returns channel pointer if successful, %NULL otherwise.
 *
 *	Creates a channel buffer for each cpu using the sizes and
 *	attributes specified.  The created channel buffer files
 *	will be named base_filename0...base_filenameN-1.  File
 *	permissions will be %S_IRUSR.
 */
struct rchan *ltt_relay_open(const char *base_filename,
			 struct dentry *parent,
			 size_t subbuf_size,
			 size_t n_subbufs,
			 void *private_data)
{
	unsigned int i;
	struct rchan *chan;
//ust//	if (!base_filename)
//ust//		return NULL;

	if (!(subbuf_size && n_subbufs))
		return NULL;

	chan = kzalloc(sizeof(struct rchan), GFP_KERNEL);
	if (!chan)
		return NULL;

	chan->version = LTT_RELAY_CHANNEL_VERSION;
	chan->n_subbufs = n_subbufs;
	chan->subbuf_size = subbuf_size;
	chan->subbuf_size_order = get_count_order(subbuf_size);
	chan->alloc_size = FIX_SIZE(subbuf_size * n_subbufs);
	chan->parent = parent;
	chan->private_data = private_data;
//ust//	strlcpy(chan->base_filename, base_filename, NAME_MAX);
//ust//	setup_callbacks(chan, cb);
	kref_init(&chan->kref);

	mutex_lock(&relay_channels_mutex);
//ust//	for_each_online_cpu(i) {
		chan->buf = relay_open_buf(chan);
		if (!chan->buf)
			goto error;
//ust//	}
	list_add(&chan->list, &relay_channels);
	mutex_unlock(&relay_channels_mutex);

	return chan;

//ust//free_bufs:
//ust//	for_each_possible_cpu(i) {
//ust//		if (!chan->buf[i])
//ust//			break;
//ust//		relay_close_buf(chan->buf[i]);
//ust//	}

	error:
	kref_put(&chan->kref, relay_destroy_channel);
	mutex_unlock(&relay_channels_mutex);
	return NULL;
}
//ust// EXPORT_SYMBOL_GPL(ltt_relay_open);

/**
 *	ltt_relay_close - close the channel
 *	@chan: the channel
 *
 *	Closes all channel buffers and frees the channel.
 */
void ltt_relay_close(struct rchan *chan)
{
	unsigned int i;

	if (!chan)
		return;

	mutex_lock(&relay_channels_mutex);
//ust//	for_each_possible_cpu(i)
		if (chan->buf)
			relay_close_buf(chan->buf);

	list_del(&chan->list);
	kref_put(&chan->kref, relay_destroy_channel);
	mutex_unlock(&relay_channels_mutex);
}
//ust// EXPORT_SYMBOL_GPL(ltt_relay_close);

/*
 * Start iteration at the previous element. Skip the real list head.
 */
//ust// struct buf_page *ltt_relay_find_prev_page(struct rchan_buf *buf,
//ust// 	struct buf_page *page, size_t offset, ssize_t diff_offset)
//ust// {
//ust// 	struct buf_page *iter;
//ust// 	size_t orig_iter_off;
//ust// 	unsigned int i = 0;
//ust// 
//ust// 	orig_iter_off = page->offset;
//ust// 	list_for_each_entry_reverse(iter, &page->list, list) {
//ust// 		/*
//ust// 		 * Skip the real list head.
//ust// 		 */
//ust// 		if (&iter->list == &buf->pages)
//ust// 			continue;
//ust// 		i++;
//ust// 		if (offset >= iter->offset
//ust// 			&& offset < iter->offset + PAGE_SIZE) {
//ust// #ifdef CONFIG_LTT_RELAY_CHECK_RANDOM_ACCESS
//ust// 			if (i > 1) {
//ust// 				printk(KERN_WARNING
//ust// 					"Backward random access detected in "
//ust// 					"ltt_relay. Iterations %u, "
//ust// 					"offset %zu, orig iter->off %zu, "
//ust// 					"iter->off %zu diff_offset %zd.\n", i,
//ust// 					offset, orig_iter_off, iter->offset,
//ust// 					diff_offset);
//ust// 				WARN_ON(1);
//ust// 			}
//ust// #endif
//ust// 			return iter;
//ust// 		}
//ust// 	}
//ust// 	WARN_ON(1);
//ust// 	return NULL;
//ust// }
//ust// EXPORT_SYMBOL_GPL(ltt_relay_find_prev_page);

/*
 * Start iteration at the next element. Skip the real list head.
 */
//ust// struct buf_page *ltt_relay_find_next_page(struct rchan_buf *buf,
//ust// 	struct buf_page *page, size_t offset, ssize_t diff_offset)
//ust// {
//ust// 	struct buf_page *iter;
//ust// 	unsigned int i = 0;
//ust// 	size_t orig_iter_off;
//ust// 
//ust// 	orig_iter_off = page->offset;
//ust// 	list_for_each_entry(iter, &page->list, list) {
//ust// 		/*
//ust// 		 * Skip the real list head.
//ust// 		 */
//ust// 		if (&iter->list == &buf->pages)
//ust// 			continue;
//ust// 		i++;
//ust// 		if (offset >= iter->offset
//ust// 			&& offset < iter->offset + PAGE_SIZE) {
//ust// #ifdef CONFIG_LTT_RELAY_CHECK_RANDOM_ACCESS
//ust// 			if (i > 1) {
//ust// 				printk(KERN_WARNING
//ust// 					"Forward random access detected in "
//ust// 					"ltt_relay. Iterations %u, "
//ust// 					"offset %zu, orig iter->off %zu, "
//ust// 					"iter->off %zu diff_offset %zd.\n", i,
//ust// 					offset, orig_iter_off, iter->offset,
//ust// 					diff_offset);
//ust// 				WARN_ON(1);
//ust// 			}
//ust// #endif
//ust// 			return iter;
//ust// 		}
//ust// 	}
//ust// 	WARN_ON(1);
//ust// 	return NULL;
//ust// }
//ust// EXPORT_SYMBOL_GPL(ltt_relay_find_next_page);

/**
 * ltt_relay_write - write data to a ltt_relay buffer.
 * @buf : buffer
 * @offset : offset within the buffer
 * @src : source address
 * @len : length to write
 * @page : cached buffer page
 * @pagecpy : page size copied so far
 */
void _ltt_relay_write(struct rchan_buf *buf, size_t offset,
	const void *src, size_t len, ssize_t cpy)
{
	do {
		len -= cpy;
		src += cpy;
		offset += cpy;
		/*
		 * Underlying layer should never ask for writes across
		 * subbuffers.
		 */
		WARN_ON(offset >= buf->buf_size);

		cpy = min_t(size_t, len, buf->buf_size - offset);
		ltt_relay_do_copy(buf->buf_data + offset, src, cpy);
	} while (unlikely(len != cpy));
}
//ust// EXPORT_SYMBOL_GPL(_ltt_relay_write);

/**
 * ltt_relay_read - read data from ltt_relay_buffer.
 * @buf : buffer
 * @offset : offset within the buffer
 * @dest : destination address
 * @len : length to write
 */
//ust// int ltt_relay_read(struct rchan_buf *buf, size_t offset,
//ust// 	void *dest, size_t len)
//ust// {
//ust// 	struct buf_page *page;
//ust// 	ssize_t pagecpy, orig_len;
//ust// 
//ust// 	orig_len = len;
//ust// 	offset &= buf->chan->alloc_size - 1;
//ust// 	page = buf->rpage;
//ust// 	if (unlikely(!len))
//ust// 		return 0;
//ust// 	for (;;) {
//ust// 		page = ltt_relay_cache_page(buf, &buf->rpage, page, offset);
//ust// 		pagecpy = min_t(size_t, len, PAGE_SIZE - (offset & ~PAGE_MASK));
//ust// 		memcpy(dest, page_address(page->page) + (offset & ~PAGE_MASK),
//ust// 			pagecpy);
//ust// 		len -= pagecpy;
//ust// 		if (likely(!len))
//ust// 			break;
//ust// 		dest += pagecpy;
//ust// 		offset += pagecpy;
//ust// 		/*
//ust// 		 * Underlying layer should never ask for reads across
//ust// 		 * subbuffers.
//ust// 		 */
//ust// 		WARN_ON(offset >= buf->chan->alloc_size);
//ust// 	}
//ust// 	return orig_len;
//ust// }
//ust// EXPORT_SYMBOL_GPL(ltt_relay_read);

/**
 * ltt_relay_read_get_page - Get a whole page to read from
 * @buf : buffer
 * @offset : offset within the buffer
 */
//ust// struct buf_page *ltt_relay_read_get_page(struct rchan_buf *buf, size_t offset)
//ust// {
//ust// 	struct buf_page *page;

//ust// 	offset &= buf->chan->alloc_size - 1;
//ust// 	page = buf->rpage;
//ust// 	page = ltt_relay_cache_page(buf, &buf->rpage, page, offset);
//ust// 	return page;
//ust// }
//ust// EXPORT_SYMBOL_GPL(ltt_relay_read_get_page);

/**
 * ltt_relay_offset_address - get address of a location within the buffer
 * @buf : buffer
 * @offset : offset within the buffer.
 *
 * Return the address where a given offset is located.
 * Should be used to get the current subbuffer header pointer. Given we know
 * it's never on a page boundary, it's safe to write directly to this address,
 * as long as the write is never bigger than a page size.
 */
void *ltt_relay_offset_address(struct rchan_buf *buf, size_t offset)
{
//ust// 	struct buf_page *page;
//ust// 	unsigned int odd;
//ust// 
//ust// 	offset &= buf->chan->alloc_size - 1;
//ust// 	odd = !!(offset & buf->chan->subbuf_size);
//ust// 	page = buf->hpage[odd];
//ust// 	if (offset < page->offset || offset >= page->offset + PAGE_SIZE)
//ust// 		buf->hpage[odd] = page = buf->wpage;
//ust// 	page = ltt_relay_cache_page(buf, &buf->hpage[odd], page, offset);
//ust// 	return page_address(page->page) + (offset & ~PAGE_MASK);
	return ((char *)buf->buf_data)+offset;
	return NULL;
}
//ust// EXPORT_SYMBOL_GPL(ltt_relay_offset_address);

/**
 *	relay_file_open - open file op for relay files
 *	@inode: the inode
 *	@filp: the file
 *
 *	Increments the channel buffer refcount.
 */
//ust// static int relay_file_open(struct inode *inode, struct file *filp)
//ust// {
//ust// 	struct rchan_buf *buf = inode->i_private;
//ust// 	kref_get(&buf->kref);
//ust// 	filp->private_data = buf;
//ust// 
//ust// 	return nonseekable_open(inode, filp);
//ust// }

/**
 *	relay_file_release - release file op for relay files
 *	@inode: the inode
 *	@filp: the file
 *
 *	Decrements the channel refcount, as the filesystem is
 *	no longer using it.
 */
//ust// static int relay_file_release(struct inode *inode, struct file *filp)
//ust// {
//ust// 	struct rchan_buf *buf = filp->private_data;
//ust// 	kref_put(&buf->kref, relay_remove_buf);
//ust// 
//ust// 	return 0;
//ust// }

//ust// const struct file_operations ltt_relay_file_operations = {
//ust// 	.open		= relay_file_open,
//ust// 	.release	= relay_file_release,
//ust// };
//ust// EXPORT_SYMBOL_GPL(ltt_relay_file_operations);

//ust// static __init int relay_init(void)
//ust// {
//ust// 	hotcpu_notifier(relay_hotcpu_callback, 5);
//ust// 	return 0;
//ust// }

//ust// module_init(relay_init);
/*
 * ltt/ltt-relay.c
 *
 * (C) Copyright 2005-2008 - Mathieu Desnoyers (mathieu.desnoyers@polymtl.ca)
 *
 * LTTng lockless buffer space management (reader/writer).
 *
 * Author:
 *	Mathieu Desnoyers (mathieu.desnoyers@polymtl.ca)
 *
 * Inspired from LTT :
 *  Karim Yaghmour (karim@opersys.com)
 *  Tom Zanussi (zanussi@us.ibm.com)
 *  Bob Wisniewski (bob@watson.ibm.com)
 * And from K42 :
 *  Bob Wisniewski (bob@watson.ibm.com)
 *
 * Changelog:
 *  08/10/08, Cleanup.
 *  19/10/05, Complete lockless mechanism.
 *  27/05/05, Modular redesign and rewrite.
 *
 * Userspace reader semantic :
 * while (poll fd != POLLHUP) {
 *   - ioctl RELAY_GET_SUBBUF_SIZE
 *   while (1) {
 *     - ioctl GET_SUBBUF
 *     - splice 1 subbuffer worth of data to a pipe
 *     - splice the data from pipe to disk/network
 *     - ioctl PUT_SUBBUF, check error value
 *       if err val < 0, previous subbuffer was corrupted.
 *   }
 * }
 */

//ust// #include <linux/time.h>
//ust// #include <linux/ltt-tracer.h>
//ust// #include <linux/ltt-relay.h>
//ust// #include <linux/module.h>
//ust// #include <linux/string.h>
//ust// #include <linux/slab.h>
//ust// #include <linux/init.h>
//ust// #include <linux/rcupdate.h>
//ust// #include <linux/sched.h>
//ust// #include <linux/bitops.h>
//ust// #include <linux/fs.h>
//ust// #include <linux/smp_lock.h>
//ust// #include <linux/debugfs.h>
//ust// #include <linux/stat.h>
//ust// #include <linux/cpu.h>
//ust// #include <linux/pipe_fs_i.h>
//ust// #include <linux/splice.h>
//ust// #include <asm/atomic.h>
//ust// #include <asm/local.h>

#if 0
#define printk_dbg(fmt, args...) printk(fmt, args)
#else
#define printk_dbg(fmt, args...)
#endif

/*
 * Last TSC comparison functions. Check if the current TSC overflows
 * LTT_TSC_BITS bits from the last TSC read. Reads and writes last_tsc
 * atomically.
 */

#if (BITS_PER_LONG == 32)
static inline void save_last_tsc(struct ltt_channel_buf_struct *ltt_buf,
					u64 tsc)
{
	ltt_buf->last_tsc = (unsigned long)(tsc >> LTT_TSC_BITS);
}

static inline int last_tsc_overflow(struct ltt_channel_buf_struct *ltt_buf,
					u64 tsc)
{
	unsigned long tsc_shifted = (unsigned long)(tsc >> LTT_TSC_BITS);

	if (unlikely((tsc_shifted - ltt_buf->last_tsc)))
		return 1;
	else
		return 0;
}
#else
static inline void save_last_tsc(struct ltt_channel_buf_struct *ltt_buf,
					u64 tsc)
{
	ltt_buf->last_tsc = (unsigned long)tsc;
}

static inline int last_tsc_overflow(struct ltt_channel_buf_struct *ltt_buf,
					u64 tsc)
{
	if (unlikely((tsc - ltt_buf->last_tsc) >> LTT_TSC_BITS))
		return 1;
	else
		return 0;
}
#endif

//ust// static struct file_operations ltt_file_operations;

/*
 * A switch is done during tracing or as a final flush after tracing (so it
 * won't write in the new sub-buffer).
 */
enum force_switch_mode { FORCE_ACTIVE, FORCE_FLUSH };

static int ltt_relay_create_buffer(struct ltt_trace_struct *trace,
		struct ltt_channel_struct *ltt_chan,
		struct rchan_buf *buf,
		unsigned int n_subbufs);

static void ltt_relay_destroy_buffer(struct ltt_channel_struct *ltt_chan);

static void ltt_force_switch(struct rchan_buf *buf,
		enum force_switch_mode mode);

/*
 * Trace callbacks
 */
static void ltt_buffer_begin_callback(struct rchan_buf *buf,
			u64 tsc, unsigned int subbuf_idx)
{
	struct ltt_channel_struct *channel =
		(struct ltt_channel_struct *)buf->chan->private_data;
	struct ltt_subbuffer_header *header =
		(struct ltt_subbuffer_header *)
			ltt_relay_offset_address(buf,
				subbuf_idx * buf->chan->subbuf_size);

	header->cycle_count_begin = tsc;
	header->lost_size = 0xFFFFFFFF; /* for debugging */
	header->buf_size = buf->chan->subbuf_size;
	ltt_write_trace_header(channel->trace, header);
}

/*
 * offset is assumed to never be 0 here : never deliver a completely empty
 * subbuffer. The lost size is between 0 and subbuf_size-1.
 */
static notrace void ltt_buffer_end_callback(struct rchan_buf *buf,
		u64 tsc, unsigned int offset, unsigned int subbuf_idx)
{
	struct ltt_channel_struct *channel =
		(struct ltt_channel_struct *)buf->chan->private_data;
	struct ltt_channel_buf_struct *ltt_buf = channel->buf;
	struct ltt_subbuffer_header *header =
		(struct ltt_subbuffer_header *)
			ltt_relay_offset_address(buf,
				subbuf_idx * buf->chan->subbuf_size);

	header->lost_size = SUBBUF_OFFSET((buf->chan->subbuf_size - offset),
				buf->chan);
	header->cycle_count_end = tsc;
	header->events_lost = local_read(&ltt_buf->events_lost);
	header->subbuf_corrupt = local_read(&ltt_buf->corrupted_subbuffers);

}

void (*wake_consumer)(void *, int) = NULL;

void relay_set_wake_consumer(void (*wake)(void *, int))
{
	wake_consumer = wake;
}

void relay_wake_consumer(void *arg, int finished)
{
	if(wake_consumer)
		wake_consumer(arg, finished);
}

static notrace void ltt_deliver(struct rchan_buf *buf, unsigned int subbuf_idx,
		long commit_count)
{
	struct ltt_channel_struct *channel =
		(struct ltt_channel_struct *)buf->chan->private_data;
	struct ltt_channel_buf_struct *ltt_buf = channel->buf;
	int result;

//ust// #ifdef CONFIG_LTT_VMCORE
	local_set(&ltt_buf->commit_seq[subbuf_idx], commit_count);
//ust// #endif

	/* wakeup consumer */
	result = write(ltt_buf->data_ready_fd_write, "1", 1);
	if(result == -1) {
		PERROR("write (in ltt_relay_buffer_flush)");
		ERR("this should never happen!");
	}
//ust//	atomic_set(&ltt_buf->wakeup_readers, 1);
}

static struct dentry *ltt_create_buf_file_callback(struct rchan_buf *buf)
{
	struct ltt_channel_struct *ltt_chan;
	int err;
//ust//	struct dentry *dentry;

	ltt_chan = buf->chan->private_data;
	err = ltt_relay_create_buffer(ltt_chan->trace, ltt_chan, buf, buf->chan->n_subbufs);
	if (err)
		return ERR_PTR(err);

//ust//	dentry = debugfs_create_file(filename, mode, parent, buf,
//ust//			&ltt_file_operations);
//ust//	if (!dentry)
//ust//		goto error;
//ust//	return dentry;
	return NULL; //ust//
//ust//error:
	ltt_relay_destroy_buffer(ltt_chan);
	return NULL;
}

static int ltt_remove_buf_file_callback(struct rchan_buf *buf)
{
//ust//	struct rchan_buf *buf = dentry->d_inode->i_private;
	struct ltt_channel_struct *ltt_chan = buf->chan->private_data;

//ust//	debugfs_remove(dentry);
	ltt_relay_destroy_buffer(ltt_chan);

	return 0;
}

/*
 * Wake writers :
 *
 * This must be done after the trace is removed from the RCU list so that there
 * are no stalled writers.
 */
//ust// static void ltt_relay_wake_writers(struct ltt_channel_buf_struct *ltt_buf)
//ust// {
//ust// 
//ust// 	if (waitqueue_active(&ltt_buf->write_wait))
//ust// 		wake_up_interruptible(&ltt_buf->write_wait);
//ust// }

/*
 * This function should not be called from NMI interrupt context
 */
static notrace void ltt_buf_unfull(struct rchan_buf *buf,
		unsigned int subbuf_idx,
		long offset)
{
//ust//	struct ltt_channel_struct *ltt_channel =
//ust//		(struct ltt_channel_struct *)buf->chan->private_data;
//ust//	struct ltt_channel_buf_struct *ltt_buf = ltt_channel->buf;
//ust//
//ust//	ltt_relay_wake_writers(ltt_buf);
}

/**
 *	ltt_open - open file op for ltt files
 *	@inode: opened inode
 *	@file: opened file
 *
 *	Open implementation. Makes sure only one open instance of a buffer is
 *	done at a given moment.
 */
//ust// static int ltt_open(struct inode *inode, struct file *file)
//ust// {
//ust// 	struct rchan_buf *buf = inode->i_private;
//ust// 	struct ltt_channel_struct *ltt_channel =
//ust// 		(struct ltt_channel_struct *)buf->chan->private_data;
//ust// 	struct ltt_channel_buf_struct *ltt_buf =
//ust// 		percpu_ptr(ltt_channel->buf, buf->cpu);
//ust// 
//ust// 	if (!atomic_long_add_unless(&ltt_buf->active_readers, 1, 1))
//ust// 		return -EBUSY;
//ust// 	return ltt_relay_file_operations.open(inode, file);
//ust// }

/**
 *	ltt_release - release file op for ltt files
 *	@inode: opened inode
 *	@file: opened file
 *
 *	Release implementation.
 */
//ust// static int ltt_release(struct inode *inode, struct file *file)
//ust// {
//ust// 	struct rchan_buf *buf = inode->i_private;
//ust// 	struct ltt_channel_struct *ltt_channel =
//ust// 		(struct ltt_channel_struct *)buf->chan->private_data;
//ust// 	struct ltt_channel_buf_struct *ltt_buf =
//ust// 		percpu_ptr(ltt_channel->buf, buf->cpu);
//ust// 	int ret;
//ust// 
//ust// 	WARN_ON(atomic_long_read(&ltt_buf->active_readers) != 1);
//ust// 	atomic_long_dec(&ltt_buf->active_readers);
//ust// 	ret = ltt_relay_file_operations.release(inode, file);
//ust// 	WARN_ON(ret);
//ust// 	return ret;
//ust// }

/**
 *	ltt_poll - file op for ltt files
 *	@filp: the file
 *	@wait: poll table
 *
 *	Poll implementation.
 */
//ust// static unsigned int ltt_poll(struct file *filp, poll_table *wait)
//ust// {
//ust// 	unsigned int mask = 0;
//ust// 	struct inode *inode = filp->f_dentry->d_inode;
//ust// 	struct rchan_buf *buf = inode->i_private;
//ust// 	struct ltt_channel_struct *ltt_channel =
//ust// 		(struct ltt_channel_struct *)buf->chan->private_data;
//ust// 	struct ltt_channel_buf_struct *ltt_buf =
//ust// 		percpu_ptr(ltt_channel->buf, buf->cpu);
//ust// 
//ust// 	if (filp->f_mode & FMODE_READ) {
//ust// 		poll_wait_set_exclusive(wait);
//ust// 		poll_wait(filp, &buf->read_wait, wait);
//ust// 
//ust// 		WARN_ON(atomic_long_read(&ltt_buf->active_readers) != 1);
//ust// 		if (SUBBUF_TRUNC(local_read(&ltt_buf->offset),
//ust// 							buf->chan)
//ust// 		  - SUBBUF_TRUNC(atomic_long_read(&ltt_buf->consumed),
//ust// 							buf->chan)
//ust// 		  == 0) {
//ust// 			if (buf->finalized)
//ust// 				return POLLHUP;
//ust// 			else
//ust// 				return 0;
//ust// 		} else {
//ust// 			struct rchan *rchan =
//ust// 				ltt_channel->trans_channel_data;
//ust// 			if (SUBBUF_TRUNC(local_read(&ltt_buf->offset),
//ust// 					buf->chan)
//ust// 			  - SUBBUF_TRUNC(atomic_long_read(
//ust// 						&ltt_buf->consumed),
//ust// 					buf->chan)
//ust// 			  >= rchan->alloc_size)
//ust// 				return POLLPRI | POLLRDBAND;
//ust// 			else
//ust// 				return POLLIN | POLLRDNORM;
//ust// 		}
//ust// 	}
//ust// 	return mask;
//ust// }

int ltt_do_get_subbuf(struct rchan_buf *buf, struct ltt_channel_buf_struct *ltt_buf, long *pconsumed_old)
{
	struct ltt_channel_struct *ltt_channel = (struct ltt_channel_struct *)buf->chan->private_data;
	long consumed_old, consumed_idx, commit_count, write_offset;
	consumed_old = atomic_long_read(&ltt_buf->consumed);
	consumed_idx = SUBBUF_INDEX(consumed_old, buf->chan);
	commit_count = local_read(&ltt_buf->commit_count[consumed_idx]);
	/*
	 * Make sure we read the commit count before reading the buffer
	 * data and the write offset. Correct consumed offset ordering
	 * wrt commit count is insured by the use of cmpxchg to update
	 * the consumed offset.
	 */
	smp_rmb();
	write_offset = local_read(&ltt_buf->offset);
	/*
	 * Check that the subbuffer we are trying to consume has been
	 * already fully committed.
	 */
	if (((commit_count - buf->chan->subbuf_size)
	     & ltt_channel->commit_count_mask)
	    - (BUFFER_TRUNC(consumed_old, buf->chan)
	       >> ltt_channel->n_subbufs_order)
	    != 0) {
		return -EAGAIN;
	}
	/*
	 * Check that we are not about to read the same subbuffer in
	 * which the writer head is.
	 */
	if ((SUBBUF_TRUNC(write_offset, buf->chan)
	   - SUBBUF_TRUNC(consumed_old, buf->chan))
	   == 0) {
		return -EAGAIN;
	}

	*pconsumed_old = consumed_old;
	return 0;
}

int ltt_do_put_subbuf(struct rchan_buf *buf, struct ltt_channel_buf_struct *ltt_buf, u32 uconsumed_old)
{
	long consumed_new, consumed_old;

	consumed_old = atomic_long_read(&ltt_buf->consumed);
	consumed_old = consumed_old & (~0xFFFFFFFFL);
	consumed_old = consumed_old | uconsumed_old;
	consumed_new = SUBBUF_ALIGN(consumed_old, buf->chan);

//ust//	spin_lock(&ltt_buf->full_lock);
	if (atomic_long_cmpxchg(&ltt_buf->consumed, consumed_old,
				consumed_new)
	    != consumed_old) {
		/* We have been pushed by the writer : the last
		 * buffer read _is_ corrupted! It can also
		 * happen if this is a buffer we never got. */
//ust//		spin_unlock(&ltt_buf->full_lock);
		return -EIO;
	} else {
		/* tell the client that buffer is now unfull */
		int index;
		long data;
		index = SUBBUF_INDEX(consumed_old, buf->chan);
		data = BUFFER_OFFSET(consumed_old, buf->chan);
		ltt_buf_unfull(buf, index, data);
//ust//		spin_unlock(&ltt_buf->full_lock);
	}
	return 0;
}

/**
 *	ltt_ioctl - control on the debugfs file
 *
 *	@inode: the inode
 *	@filp: the file
 *	@cmd: the command
 *	@arg: command arg
 *
 *	This ioctl implements three commands necessary for a minimal
 *	producer/consumer implementation :
 *	RELAY_GET_SUBBUF
 *		Get the next sub buffer that can be read. It never blocks.
 *	RELAY_PUT_SUBBUF
 *		Release the currently read sub-buffer. Parameter is the last
 *		put subbuffer (returned by GET_SUBBUF).
 *	RELAY_GET_N_BUBBUFS
 *		returns the number of sub buffers in the per cpu channel.
 *	RELAY_GET_SUBBUF_SIZE
 *		returns the size of the sub buffers.
 */
//ust// static int ltt_ioctl(struct inode *inode, struct file *filp,
//ust// 		unsigned int cmd, unsigned long arg)
//ust// {
//ust// 	struct rchan_buf *buf = inode->i_private;
//ust// 	struct ltt_channel_struct *ltt_channel =
//ust// 		(struct ltt_channel_struct *)buf->chan->private_data;
//ust// 	struct ltt_channel_buf_struct *ltt_buf =
//ust// 		percpu_ptr(ltt_channel->buf, buf->cpu);
//ust// 	u32 __user *argp = (u32 __user *)arg;
//ust// 
//ust// 	WARN_ON(atomic_long_read(&ltt_buf->active_readers) != 1);
//ust// 	switch (cmd) {
//ust// 	case RELAY_GET_SUBBUF:
//ust// 	{
//ust// 		int ret;
//ust// 		ret = ltt_do_get_subbuf(buf, ltt_buf, &consumed_old);
//ust// 		if(ret < 0)
//ust// 			return ret;
//ust// 		return put_user((u32)consumed_old, argp);
//ust// 	}
//ust// 	case RELAY_PUT_SUBBUF:
//ust// 	{
//ust// 		int ret;
//ust// 		u32 uconsumed_old;
//ust// 		ret = get_user(uconsumed_old, argp);
//ust// 		if (ret)
//ust// 			return ret; /* will return -EFAULT */
//ust// 		return ltt_do_put_subbuf(buf, ltt_buf, uconsumed_old);
//ust// 	}
//ust// 	case RELAY_GET_N_SUBBUFS:
//ust// 		return put_user((u32)buf->chan->n_subbufs, argp);
//ust// 		break;
//ust// 	case RELAY_GET_SUBBUF_SIZE:
//ust// 		return put_user((u32)buf->chan->subbuf_size, argp);
//ust// 		break;
//ust// 	default:
//ust// 		return -ENOIOCTLCMD;
//ust// 	}
//ust// 	return 0;
//ust// }

//ust// #ifdef CONFIG_COMPAT
//ust// static long ltt_compat_ioctl(struct file *file, unsigned int cmd,
//ust// 		unsigned long arg)
//ust// {
//ust// 	long ret = -ENOIOCTLCMD;
//ust// 
//ust// 	lock_kernel();
//ust// 	ret = ltt_ioctl(file->f_dentry->d_inode, file, cmd, arg);
//ust// 	unlock_kernel();
//ust// 
//ust// 	return ret;
//ust// }
//ust// #endif

//ust// static void ltt_relay_pipe_buf_release(struct pipe_inode_info *pipe,
//ust// 				   struct pipe_buffer *pbuf)
//ust// {
//ust// }
//ust// 
//ust// static struct pipe_buf_operations ltt_relay_pipe_buf_ops = {
//ust// 	.can_merge = 0,
//ust// 	.map = generic_pipe_buf_map,
//ust// 	.unmap = generic_pipe_buf_unmap,
//ust// 	.confirm = generic_pipe_buf_confirm,
//ust// 	.release = ltt_relay_pipe_buf_release,
//ust// 	.steal = generic_pipe_buf_steal,
//ust// 	.get = generic_pipe_buf_get,
//ust// };

//ust// static void ltt_relay_page_release(struct splice_pipe_desc *spd, unsigned int i)
//ust// {
//ust// }

/*
 *	subbuf_splice_actor - splice up to one subbuf's worth of data
 */
//ust// static int subbuf_splice_actor(struct file *in,
//ust// 			       loff_t *ppos,
//ust// 			       struct pipe_inode_info *pipe,
//ust// 			       size_t len,
//ust// 			       unsigned int flags)
//ust// {
//ust// 	struct rchan_buf *buf = in->private_data;
//ust// 	struct ltt_channel_struct *ltt_channel =
//ust// 		(struct ltt_channel_struct *)buf->chan->private_data;
//ust// 	struct ltt_channel_buf_struct *ltt_buf =
//ust// 		percpu_ptr(ltt_channel->buf, buf->cpu);
//ust// 	unsigned int poff, subbuf_pages, nr_pages;
//ust// 	struct page *pages[PIPE_BUFFERS];
//ust// 	struct partial_page partial[PIPE_BUFFERS];
//ust// 	struct splice_pipe_desc spd = {
//ust// 		.pages = pages,
//ust// 		.nr_pages = 0,
//ust// 		.partial = partial,
//ust// 		.flags = flags,
//ust// 		.ops = &ltt_relay_pipe_buf_ops,
//ust// 		.spd_release = ltt_relay_page_release,
//ust// 	};
//ust// 	long consumed_old, consumed_idx, roffset;
//ust// 	unsigned long bytes_avail;
//ust// 
//ust// 	/*
//ust// 	 * Check that a GET_SUBBUF ioctl has been done before.
//ust// 	 */
//ust// 	WARN_ON(atomic_long_read(&ltt_buf->active_readers) != 1);
//ust// 	consumed_old = atomic_long_read(&ltt_buf->consumed);
//ust// 	consumed_old += *ppos;
//ust// 	consumed_idx = SUBBUF_INDEX(consumed_old, buf->chan);
//ust// 
//ust// 	/*
//ust// 	 * Adjust read len, if longer than what is available
//ust// 	 */
//ust// 	bytes_avail = SUBBUF_TRUNC(local_read(&ltt_buf->offset), buf->chan)
//ust// 		    - consumed_old;
//ust// 	WARN_ON(bytes_avail > buf->chan->alloc_size);
//ust// 	len = min_t(size_t, len, bytes_avail);
//ust// 	subbuf_pages = bytes_avail >> PAGE_SHIFT;
//ust// 	nr_pages = min_t(unsigned int, subbuf_pages, PIPE_BUFFERS);
//ust// 	roffset = consumed_old & PAGE_MASK;
//ust// 	poff = consumed_old & ~PAGE_MASK;
//ust// 	printk_dbg(KERN_DEBUG "SPLICE actor len %zu pos %zd write_pos %ld\n",
//ust// 		len, (ssize_t)*ppos, local_read(&ltt_buf->offset));
//ust// 
//ust// 	for (; spd.nr_pages < nr_pages; spd.nr_pages++) {
//ust// 		unsigned int this_len;
//ust// 		struct buf_page *page;
//ust// 
//ust// 		if (!len)
//ust// 			break;
//ust// 		printk_dbg(KERN_DEBUG "SPLICE actor loop len %zu roffset %ld\n",
//ust// 			len, roffset);
//ust// 
//ust// 		this_len = PAGE_SIZE - poff;
//ust// 		page = ltt_relay_read_get_page(buf, roffset);
//ust// 		spd.pages[spd.nr_pages] = page->page;
//ust// 		spd.partial[spd.nr_pages].offset = poff;
//ust// 		spd.partial[spd.nr_pages].len = this_len;
//ust// 
//ust// 		poff = 0;
//ust// 		roffset += PAGE_SIZE;
//ust// 		len -= this_len;
//ust// 	}
//ust// 
//ust// 	if (!spd.nr_pages)
//ust// 		return 0;
//ust// 
//ust// 	return splice_to_pipe(pipe, &spd);
//ust// }

//ust// static ssize_t ltt_relay_file_splice_read(struct file *in,
//ust// 				      loff_t *ppos,
//ust// 				      struct pipe_inode_info *pipe,
//ust// 				      size_t len,
//ust// 				      unsigned int flags)
//ust// {
//ust// 	ssize_t spliced;
//ust// 	int ret;
//ust// 
//ust// 	ret = 0;
//ust// 	spliced = 0;
//ust// 
//ust// 	printk_dbg(KERN_DEBUG "SPLICE read len %zu pos %zd\n",
//ust// 		len, (ssize_t)*ppos);
//ust// 	while (len && !spliced) {
//ust// 		ret = subbuf_splice_actor(in, ppos, pipe, len, flags);
//ust// 		printk_dbg(KERN_DEBUG "SPLICE read loop ret %d\n", ret);
//ust// 		if (ret < 0)
//ust// 			break;
//ust// 		else if (!ret) {
//ust// 			if (flags & SPLICE_F_NONBLOCK)
//ust// 				ret = -EAGAIN;
//ust// 			break;
//ust// 		}
//ust// 
//ust// 		*ppos += ret;
//ust// 		if (ret > len)
//ust// 			len = 0;
//ust// 		else
//ust// 			len -= ret;
//ust// 		spliced += ret;
//ust// 	}
//ust// 
//ust// 	if (spliced)
//ust// 		return spliced;
//ust// 
//ust// 	return ret;
//ust// }

static void ltt_relay_print_subbuffer_errors(
		struct ltt_channel_struct *ltt_chan,
		long cons_off)
{
	struct rchan *rchan = ltt_chan->trans_channel_data;
	struct ltt_channel_buf_struct *ltt_buf = ltt_chan->buf;
	long cons_idx, commit_count, write_offset;

	cons_idx = SUBBUF_INDEX(cons_off, rchan);
	commit_count = local_read(&ltt_buf->commit_count[cons_idx]);
	/*
	 * No need to order commit_count and write_offset reads because we
	 * execute after trace is stopped when there are no readers left.
	 */
	write_offset = local_read(&ltt_buf->offset);
	printk(KERN_WARNING
		"LTT : unread channel %s offset is %ld "
		"and cons_off : %ld\n",
		ltt_chan->channel_name, write_offset, cons_off);
	/* Check each sub-buffer for non filled commit count */
	if (((commit_count - rchan->subbuf_size) & ltt_chan->commit_count_mask)
	    - (BUFFER_TRUNC(cons_off, rchan) >> ltt_chan->n_subbufs_order)
	    != 0)
		printk(KERN_ALERT
			"LTT : %s : subbuffer %lu has non filled "
			"commit count %lu.\n",
			ltt_chan->channel_name, cons_idx, commit_count);
	printk(KERN_ALERT "LTT : %s : commit count : %lu, subbuf size %zd\n",
			ltt_chan->channel_name, commit_count,
			rchan->subbuf_size);
}

static void ltt_relay_print_errors(struct ltt_trace_struct *trace,
		struct ltt_channel_struct *ltt_chan)
{
	struct rchan *rchan = ltt_chan->trans_channel_data;
	struct ltt_channel_buf_struct *ltt_buf = ltt_chan->buf;
	long cons_off;

	for (cons_off = atomic_long_read(&ltt_buf->consumed);
			(SUBBUF_TRUNC(local_read(&ltt_buf->offset),
				      rchan)
			 - cons_off) > 0;
			cons_off = SUBBUF_ALIGN(cons_off, rchan))
		ltt_relay_print_subbuffer_errors(ltt_chan, cons_off);
}

static void ltt_relay_print_buffer_errors(struct ltt_channel_struct *ltt_chan)
{
	struct ltt_trace_struct *trace = ltt_chan->trace;
	struct ltt_channel_buf_struct *ltt_buf = ltt_chan->buf;

	if (local_read(&ltt_buf->events_lost))
		printk(KERN_ALERT
			"LTT : %s : %ld events lost "
			"in %s channel.\n",
			ltt_chan->channel_name,
			local_read(&ltt_buf->events_lost),
			ltt_chan->channel_name);
	if (local_read(&ltt_buf->corrupted_subbuffers))
		printk(KERN_ALERT
			"LTT : %s : %ld corrupted subbuffers "
			"in %s channel.\n",
			ltt_chan->channel_name,
			local_read(&ltt_buf->corrupted_subbuffers),
			ltt_chan->channel_name);

	ltt_relay_print_errors(trace, ltt_chan);
}

static void ltt_relay_remove_dirs(struct ltt_trace_struct *trace)
{
//ust// 	debugfs_remove(trace->dentry.trace_root);
}

static void ltt_relay_release_channel(struct kref *kref)
{
	struct ltt_channel_struct *ltt_chan = container_of(kref,
			struct ltt_channel_struct, kref);
	free(ltt_chan->buf);
}

/*
 * Create ltt buffer.
 */
//ust// static int ltt_relay_create_buffer(struct ltt_trace_struct *trace,
//ust// 		struct ltt_channel_struct *ltt_chan, struct rchan_buf *buf,
//ust// 		unsigned int cpu, unsigned int n_subbufs)
//ust// {
//ust// 	struct ltt_channel_buf_struct *ltt_buf =
//ust// 		percpu_ptr(ltt_chan->buf, cpu);
//ust// 	unsigned int j;
//ust// 
//ust// 	ltt_buf->commit_count =
//ust// 		kzalloc_node(sizeof(ltt_buf->commit_count) * n_subbufs,
//ust// 			GFP_KERNEL, cpu_to_node(cpu));
//ust// 	if (!ltt_buf->commit_count)
//ust// 		return -ENOMEM;
//ust// 	kref_get(&trace->kref);
//ust// 	kref_get(&trace->ltt_transport_kref);
//ust// 	kref_get(&ltt_chan->kref);
//ust// 	local_set(&ltt_buf->offset, ltt_subbuffer_header_size());
//ust// 	atomic_long_set(&ltt_buf->consumed, 0);
//ust// 	atomic_long_set(&ltt_buf->active_readers, 0);
//ust// 	for (j = 0; j < n_subbufs; j++)
//ust// 		local_set(&ltt_buf->commit_count[j], 0);
//ust// 	init_waitqueue_head(&ltt_buf->write_wait);
//ust// 	atomic_set(&ltt_buf->wakeup_readers, 0);
//ust// 	spin_lock_init(&ltt_buf->full_lock);
//ust// 
//ust// 	ltt_buffer_begin_callback(buf, trace->start_tsc, 0);
//ust// 	/* atomic_add made on local variable on data that belongs to
//ust// 	 * various CPUs : ok because tracing not started (for this cpu). */
//ust// 	local_add(ltt_subbuffer_header_size(), &ltt_buf->commit_count[0]);
//ust// 
//ust// 	local_set(&ltt_buf->events_lost, 0);
//ust// 	local_set(&ltt_buf->corrupted_subbuffers, 0);
//ust// 
//ust// 	return 0;
//ust// }

static int ltt_relay_create_buffer(struct ltt_trace_struct *trace,
		struct ltt_channel_struct *ltt_chan, struct rchan_buf *buf,
		unsigned int n_subbufs)
{
	struct ltt_channel_buf_struct *ltt_buf = ltt_chan->buf;
	unsigned int j;
	int fds[2];
	int result;

	ltt_buf->commit_count =
		zmalloc(sizeof(ltt_buf->commit_count) * n_subbufs);
	if (!ltt_buf->commit_count)
		return -ENOMEM;
	kref_get(&trace->kref);
	kref_get(&trace->ltt_transport_kref);
	kref_get(&ltt_chan->kref);
	local_set(&ltt_buf->offset, ltt_subbuffer_header_size());
	atomic_long_set(&ltt_buf->consumed, 0);
	atomic_long_set(&ltt_buf->active_readers, 0);
	for (j = 0; j < n_subbufs; j++)
		local_set(&ltt_buf->commit_count[j], 0);
//ust//	init_waitqueue_head(&ltt_buf->write_wait);
//ust//	atomic_set(&ltt_buf->wakeup_readers, 0);
//ust//	spin_lock_init(&ltt_buf->full_lock);

	ltt_buffer_begin_callback(buf, trace->start_tsc, 0);

	local_add(ltt_subbuffer_header_size(), &ltt_buf->commit_count[0]);

	local_set(&ltt_buf->events_lost, 0);
	local_set(&ltt_buf->corrupted_subbuffers, 0);

	result = pipe(fds);
	if(result == -1) {
		PERROR("pipe");
		return -1;
	}
	ltt_buf->data_ready_fd_read = fds[0];
	ltt_buf->data_ready_fd_write = fds[1];

//ust//	ltt_buf->commit_seq = malloc(sizeof(ltt_buf->commit_seq) * n_subbufs);
//ust//	if(!ltt_buf->commit_seq) {
//ust//		return -1;
//ust//	}

	/* FIXME: decrementally destroy on error */

	return 0;
}

static void ltt_relay_destroy_buffer(struct ltt_channel_struct *ltt_chan)
{
	struct ltt_trace_struct *trace = ltt_chan->trace;
	struct ltt_channel_buf_struct *ltt_buf = ltt_chan->buf;

	kref_put(&ltt_chan->trace->ltt_transport_kref,
		ltt_release_transport);
	ltt_relay_print_buffer_errors(ltt_chan);
//ust//	free(ltt_buf->commit_seq);
	kfree(ltt_buf->commit_count);
	ltt_buf->commit_count = NULL;
	kref_put(&ltt_chan->kref, ltt_relay_release_channel);
	kref_put(&trace->kref, ltt_release_trace);
//ust//	wake_up_interruptible(&trace->kref_wq);
}

static void ltt_chan_alloc_ltt_buf(struct ltt_channel_struct *ltt_chan)
{
	void *ptr;
	int result;

	/* Get one page */
	/* FIXME: increase size if we have a seq_commit array that overflows the page */
	size_t size = PAGE_ALIGN(1);

	result = ltt_chan->buf_shmid = shmget(getpid(), size, IPC_CREAT | IPC_EXCL | 0700);
	if(ltt_chan->buf_shmid == -1) {
		PERROR("shmget");
		return -1;
	}

	ptr = shmat(ltt_chan->buf_shmid, NULL, 0);
	if(ptr == (void *) -1) {
		perror("shmat");
		goto destroy_shmem;
	}

	/* Already mark the shared memory for destruction. This will occur only
         * when all users have detached.
	 */
	result = shmctl(ltt_chan->buf_shmid, IPC_RMID, NULL);
	if(result == -1) {
		perror("shmctl");
		return -1;
	}

	ltt_chan->buf = ptr;

	return 0;

	destroy_shmem:
	result = shmctl(ltt_chan->buf_shmid, IPC_RMID, NULL);
	if(result == -1) {
		perror("shmctl");
	}

	return -1;
}

/*
 * Create channel.
 */
static int ltt_relay_create_channel(const char *trace_name,
		struct ltt_trace_struct *trace, struct dentry *dir,
		const char *channel_name, struct ltt_channel_struct *ltt_chan,
		unsigned int subbuf_size, unsigned int n_subbufs,
		int overwrite)
{
	char *tmpname;
	unsigned int tmpname_len;
	int err = 0;

	tmpname = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!tmpname)
		return EPERM;
	if (overwrite) {
		strncpy(tmpname, LTT_FLIGHT_PREFIX, PATH_MAX-1);
		strncat(tmpname, channel_name,
			PATH_MAX-1-sizeof(LTT_FLIGHT_PREFIX));
	} else {
		strncpy(tmpname, channel_name, PATH_MAX-1);
	}
	strncat(tmpname, "_", PATH_MAX-1-strlen(tmpname));

	kref_init(&ltt_chan->kref);

	ltt_chan->trace = trace;
	ltt_chan->buffer_begin = ltt_buffer_begin_callback;
	ltt_chan->buffer_end = ltt_buffer_end_callback;
	ltt_chan->overwrite = overwrite;
	ltt_chan->n_subbufs_order = get_count_order(n_subbufs);
	ltt_chan->commit_count_mask = (~0UL >> ltt_chan->n_subbufs_order);
//ust//	ltt_chan->buf = percpu_alloc_mask(sizeof(struct ltt_channel_buf_struct), GFP_KERNEL, cpu_possible_map);

	ltt_chan_alloc_ltt_buf(ltt_chan);

//ust//	ltt_chan->buf = malloc(sizeof(struct ltt_channel_buf_struct));
	if (!ltt_chan->buf)
		goto alloc_error;
	ltt_chan->trans_channel_data = ltt_relay_open(tmpname,
			dir,
			subbuf_size,
			n_subbufs,
			ltt_chan);
	tmpname_len = strlen(tmpname);
	if (tmpname_len > 0) {
		/* Remove final _ for pretty printing */
		tmpname[tmpname_len-1] = '\0';
	}
	if (ltt_chan->trans_channel_data == NULL) {
		printk(KERN_ERR "LTT : Can't open %s channel for trace %s\n",
				tmpname, trace_name);
		goto relay_open_error;
	}

	err = 0;
	goto end;

relay_open_error:
//ust//	percpu_free(ltt_chan->buf);
alloc_error:
	err = EPERM;
end:
	kfree(tmpname);
	return err;
}

static int ltt_relay_create_dirs(struct ltt_trace_struct *new_trace)
{
//ust//	new_trace->dentry.trace_root = debugfs_create_dir(new_trace->trace_name,
//ust//			get_ltt_root());
//ust//	if (new_trace->dentry.trace_root == NULL) {
//ust//		printk(KERN_ERR "LTT : Trace directory name %s already taken\n",
//ust//				new_trace->trace_name);
//ust//		return EEXIST;
//ust//	}

//ust//	new_trace->callbacks.create_buf_file = ltt_create_buf_file_callback;
//ust//	new_trace->callbacks.remove_buf_file = ltt_remove_buf_file_callback;

	return 0;
}

/*
 * LTTng channel flush function.
 *
 * Must be called when no tracing is active in the channel, because of
 * accesses across CPUs.
 */
static notrace void ltt_relay_buffer_flush(struct rchan_buf *buf)
{
	struct ltt_channel_struct *channel =
		(struct ltt_channel_struct *)buf->chan->private_data;
	struct ltt_channel_buf_struct *ltt_buf = channel->buf;
	int result;

	buf->finalized = 1;
	ltt_force_switch(buf, FORCE_FLUSH);

	result = write(ltt_buf->data_ready_fd_write, "1", 1);
	if(result == -1) {
		PERROR("write (in ltt_relay_buffer_flush)");
		ERR("this should never happen!");
	}
}

static void ltt_relay_async_wakeup_chan(struct ltt_channel_struct *ltt_channel)
{
//ust//	unsigned int i;
//ust//	struct rchan *rchan = ltt_channel->trans_channel_data;
//ust//
//ust//	for_each_possible_cpu(i) {
//ust//		struct ltt_channel_buf_struct *ltt_buf =
//ust//			percpu_ptr(ltt_channel->buf, i);
//ust//
//ust//		if (atomic_read(&ltt_buf->wakeup_readers) == 1) {
//ust//			atomic_set(&ltt_buf->wakeup_readers, 0);
//ust//			wake_up_interruptible(&rchan->buf[i]->read_wait);
//ust//		}
//ust//	}
}

static void ltt_relay_finish_buffer(struct ltt_channel_struct *ltt_channel)
{
	struct rchan *rchan = ltt_channel->trans_channel_data;
	int result;

	if (rchan->buf) {
		struct ltt_channel_buf_struct *ltt_buf = ltt_channel->buf;
		ltt_relay_buffer_flush(rchan->buf);
//ust//		ltt_relay_wake_writers(ltt_buf);
		/* closing the pipe tells the consumer the buffer is finished */
		
		//result = write(ltt_buf->data_ready_fd_write, "D", 1);
		//if(result == -1) {
		//	PERROR("write (in ltt_relay_finish_buffer)");
		//	ERR("this should never happen!");
		//}
		close(ltt_buf->data_ready_fd_write);
	}
}


static void ltt_relay_finish_channel(struct ltt_channel_struct *ltt_channel)
{
	unsigned int i;

//ust//	for_each_possible_cpu(i)
		ltt_relay_finish_buffer(ltt_channel);
}

static void ltt_relay_remove_channel(struct ltt_channel_struct *channel)
{
	struct rchan *rchan = channel->trans_channel_data;

	ltt_relay_close(rchan);
	kref_put(&channel->kref, ltt_relay_release_channel);
}

struct ltt_reserve_switch_offsets {
	long begin, end, old;
	long begin_switch, end_switch_current, end_switch_old;
	long commit_count, reserve_commit_diff;
	size_t before_hdr_pad, size;
};

/*
 * Returns :
 * 0 if ok
 * !0 if execution must be aborted.
 */
static inline int ltt_relay_try_reserve(
		struct ltt_channel_struct *ltt_channel,
		struct ltt_channel_buf_struct *ltt_buf, struct rchan *rchan,
		struct rchan_buf *buf,
		struct ltt_reserve_switch_offsets *offsets, size_t data_size,
		u64 *tsc, unsigned int *rflags, int largest_align)
{
	offsets->begin = local_read(&ltt_buf->offset);
	offsets->old = offsets->begin;
	offsets->begin_switch = 0;
	offsets->end_switch_current = 0;
	offsets->end_switch_old = 0;

	*tsc = trace_clock_read64();
	if (last_tsc_overflow(ltt_buf, *tsc))
		*rflags = LTT_RFLAG_ID_SIZE_TSC;

	if (SUBBUF_OFFSET(offsets->begin, buf->chan) == 0) {
		offsets->begin_switch = 1;		/* For offsets->begin */
	} else {
		offsets->size = ltt_get_header_size(ltt_channel,
					offsets->begin, data_size,
					&offsets->before_hdr_pad, *rflags);
		offsets->size += ltt_align(offsets->begin + offsets->size,
					   largest_align)
				 + data_size;
		if ((SUBBUF_OFFSET(offsets->begin, buf->chan) + offsets->size)
				> buf->chan->subbuf_size) {
			offsets->end_switch_old = 1;	/* For offsets->old */
			offsets->begin_switch = 1;	/* For offsets->begin */
		}
	}
	if (offsets->begin_switch) {
		long subbuf_index;

		if (offsets->end_switch_old)
			offsets->begin = SUBBUF_ALIGN(offsets->begin,
						      buf->chan);
		offsets->begin = offsets->begin + ltt_subbuffer_header_size();
		/* Test new buffer integrity */
		subbuf_index = SUBBUF_INDEX(offsets->begin, buf->chan);
		offsets->reserve_commit_diff =
			(BUFFER_TRUNC(offsets->begin, buf->chan)
			 >> ltt_channel->n_subbufs_order)
			- (local_read(&ltt_buf->commit_count[subbuf_index])
				& ltt_channel->commit_count_mask);
		if (offsets->reserve_commit_diff == 0) {
			/* Next buffer not corrupted. */
			if (!ltt_channel->overwrite &&
				(SUBBUF_TRUNC(offsets->begin, buf->chan)
				 - SUBBUF_TRUNC(atomic_long_read(
							&ltt_buf->consumed),
						buf->chan))
				>= rchan->alloc_size) {
				/*
				 * We do not overwrite non consumed buffers
				 * and we are full : event is lost.
				 */
				local_inc(&ltt_buf->events_lost);
				return -1;
			} else {
				/*
				 * next buffer not corrupted, we are either in
				 * overwrite mode or the buffer is not full.
				 * It's safe to write in this new subbuffer.
				 */
			}
		} else {
			/*
			 * Next subbuffer corrupted. Force pushing reader even
			 * in normal mode. It's safe to write in this new
			 * subbuffer.
			 */
		}
		offsets->size = ltt_get_header_size(ltt_channel,
					offsets->begin, data_size,
					&offsets->before_hdr_pad, *rflags);
		offsets->size += ltt_align(offsets->begin + offsets->size,
					   largest_align)
				 + data_size;
		if ((SUBBUF_OFFSET(offsets->begin, buf->chan) + offsets->size)
				> buf->chan->subbuf_size) {
			/*
			 * Event too big for subbuffers, report error, don't
			 * complete the sub-buffer switch.
			 */
			local_inc(&ltt_buf->events_lost);
			return -1;
		} else {
			/*
			 * We just made a successful buffer switch and the event
			 * fits in the new subbuffer. Let's write.
			 */
		}
	} else {
		/*
		 * Event fits in the current buffer and we are not on a switch
		 * boundary. It's safe to write.
		 */
	}
	offsets->end = offsets->begin + offsets->size;

	if ((SUBBUF_OFFSET(offsets->end, buf->chan)) == 0) {
		/*
		 * The offset_end will fall at the very beginning of the next
		 * subbuffer.
		 */
		offsets->end_switch_current = 1;	/* For offsets->begin */
	}
	return 0;
}

/*
 * Returns :
 * 0 if ok
 * !0 if execution must be aborted.
 */
static inline int ltt_relay_try_switch(
		enum force_switch_mode mode,
		struct ltt_channel_struct *ltt_channel,
		struct ltt_channel_buf_struct *ltt_buf, struct rchan *rchan,
		struct rchan_buf *buf,
		struct ltt_reserve_switch_offsets *offsets,
		u64 *tsc)
{
	long subbuf_index;

	offsets->begin = local_read(&ltt_buf->offset);
	offsets->old = offsets->begin;
	offsets->begin_switch = 0;
	offsets->end_switch_old = 0;

	*tsc = trace_clock_read64();

	if (SUBBUF_OFFSET(offsets->begin, buf->chan) != 0) {
		offsets->begin = SUBBUF_ALIGN(offsets->begin, buf->chan);
		offsets->end_switch_old = 1;
	} else {
		/* we do not have to switch : buffer is empty */
		return -1;
	}
	if (mode == FORCE_ACTIVE)
		offsets->begin += ltt_subbuffer_header_size();
	/*
	 * Always begin_switch in FORCE_ACTIVE mode.
	 * Test new buffer integrity
	 */
	subbuf_index = SUBBUF_INDEX(offsets->begin, buf->chan);
	offsets->reserve_commit_diff =
		(BUFFER_TRUNC(offsets->begin, buf->chan)
		 >> ltt_channel->n_subbufs_order)
		- (local_read(&ltt_buf->commit_count[subbuf_index])
			& ltt_channel->commit_count_mask);
	if (offsets->reserve_commit_diff == 0) {
		/* Next buffer not corrupted. */
		if (mode == FORCE_ACTIVE
		    && !ltt_channel->overwrite
		    && offsets->begin - atomic_long_read(&ltt_buf->consumed)
		       >= rchan->alloc_size) {
			/*
			 * We do not overwrite non consumed buffers and we are
			 * full : ignore switch while tracing is active.
			 */
			return -1;
		}
	} else {
		/*
		 * Next subbuffer corrupted. Force pushing reader even in normal
		 * mode
		 */
	}
	offsets->end = offsets->begin;
	return 0;
}

static inline void ltt_reserve_push_reader(
		struct ltt_channel_struct *ltt_channel,
		struct ltt_channel_buf_struct *ltt_buf,
		struct rchan *rchan,
		struct rchan_buf *buf,
		struct ltt_reserve_switch_offsets *offsets)
{
	long consumed_old, consumed_new;

	do {
		consumed_old = atomic_long_read(&ltt_buf->consumed);
		/*
		 * If buffer is in overwrite mode, push the reader consumed
		 * count if the write position has reached it and we are not
		 * at the first iteration (don't push the reader farther than
		 * the writer). This operation can be done concurrently by many
		 * writers in the same buffer, the writer being at the farthest
		 * write position sub-buffer index in the buffer being the one
		 * which will win this loop.
		 * If the buffer is not in overwrite mode, pushing the reader
		 * only happens if a sub-buffer is corrupted.
		 */
		if ((SUBBUF_TRUNC(offsets->end-1, buf->chan)
		   - SUBBUF_TRUNC(consumed_old, buf->chan))
		   >= rchan->alloc_size)
			consumed_new = SUBBUF_ALIGN(consumed_old, buf->chan);
		else {
			consumed_new = consumed_old;
			break;
		}
	} while (atomic_long_cmpxchg(&ltt_buf->consumed, consumed_old,
			consumed_new) != consumed_old);

	if (consumed_old != consumed_new) {
		/*
		 * Reader pushed : we are the winner of the push, we can
		 * therefore reequilibrate reserve and commit. Atomic increment
		 * of the commit count permits other writers to play around
		 * with this variable before us. We keep track of
		 * corrupted_subbuffers even in overwrite mode :
		 * we never want to write over a non completely committed
		 * sub-buffer : possible causes : the buffer size is too low
		 * compared to the unordered data input, or there is a writer
		 * that died between the reserve and the commit.
		 */
		if (offsets->reserve_commit_diff) {
			/*
			 * We have to alter the sub-buffer commit count.
			 * We do not deliver the previous subbuffer, given it
			 * was either corrupted or not consumed (overwrite
			 * mode).
			 */
			local_add(offsets->reserve_commit_diff,
				  &ltt_buf->commit_count[
					SUBBUF_INDEX(offsets->begin,
						     buf->chan)]);
			if (!ltt_channel->overwrite
			    || offsets->reserve_commit_diff
			       != rchan->subbuf_size) {
				/*
				 * The reserve commit diff was not subbuf_size :
				 * it means the subbuffer was partly written to
				 * and is therefore corrupted. If it is multiple
				 * of subbuffer size and we are in flight
				 * recorder mode, we are skipping over a whole
				 * subbuffer.
				 */
				local_inc(&ltt_buf->corrupted_subbuffers);
			}
		}
	}
}


/*
 * ltt_reserve_switch_old_subbuf: switch old subbuffer
 *
 * Concurrency safe because we are the last and only thread to alter this
 * sub-buffer. As long as it is not delivered and read, no other thread can
 * alter the offset, alter the reserve_count or call the
 * client_buffer_end_callback on this sub-buffer.
 *
 * The only remaining threads could be the ones with pending commits. They will
 * have to do the deliver themselves.  Not concurrency safe in overwrite mode.
 * We detect corrupted subbuffers with commit and reserve counts. We keep a
 * corrupted sub-buffers count and push the readers across these sub-buffers.
 *
 * Not concurrency safe if a writer is stalled in a subbuffer and another writer
 * switches in, finding out it's corrupted.  The result will be than the old
 * (uncommited) subbuffer will be declared corrupted, and that the new subbuffer
 * will be declared corrupted too because of the commit count adjustment.
 *
 * Note : offset_old should never be 0 here.
 */
static inline void ltt_reserve_switch_old_subbuf(
		struct ltt_channel_struct *ltt_channel,
		struct ltt_channel_buf_struct *ltt_buf, struct rchan *rchan,
		struct rchan_buf *buf,
		struct ltt_reserve_switch_offsets *offsets, u64 *tsc)
{
	long oldidx = SUBBUF_INDEX(offsets->old - 1, rchan);

	ltt_channel->buffer_end(buf, *tsc, offsets->old, oldidx);
	/* Must write buffer end before incrementing commit count */
	smp_wmb();
	offsets->commit_count =
		local_add_return(rchan->subbuf_size
				 - (SUBBUF_OFFSET(offsets->old - 1, rchan)
				 + 1),
				 &ltt_buf->commit_count[oldidx]);
	if ((BUFFER_TRUNC(offsets->old - 1, rchan)
			>> ltt_channel->n_subbufs_order)
			- ((offsets->commit_count - rchan->subbuf_size)
				& ltt_channel->commit_count_mask) == 0)
		ltt_deliver(buf, oldidx, offsets->commit_count);
}

/*
 * ltt_reserve_switch_new_subbuf: Populate new subbuffer.
 *
 * This code can be executed unordered : writers may already have written to the
 * sub-buffer before this code gets executed, caution.  The commit makes sure
 * that this code is executed before the deliver of this sub-buffer.
 */
static /*inline*/ void ltt_reserve_switch_new_subbuf(
		struct ltt_channel_struct *ltt_channel,
		struct ltt_channel_buf_struct *ltt_buf, struct rchan *rchan,
		struct rchan_buf *buf,
		struct ltt_reserve_switch_offsets *offsets, u64 *tsc)
{
	long beginidx = SUBBUF_INDEX(offsets->begin, rchan);

	ltt_channel->buffer_begin(buf, *tsc, beginidx);
	/* Must write buffer end before incrementing commit count */
	smp_wmb();
	offsets->commit_count = local_add_return(ltt_subbuffer_header_size(),
			&ltt_buf->commit_count[beginidx]);
	/* Check if the written buffer has to be delivered */
	if ((BUFFER_TRUNC(offsets->begin, rchan)
			>> ltt_channel->n_subbufs_order)
			- ((offsets->commit_count - rchan->subbuf_size)
				& ltt_channel->commit_count_mask) == 0)
		ltt_deliver(buf, beginidx, offsets->commit_count);
}


/*
 * ltt_reserve_end_switch_current: finish switching current subbuffer
 *
 * Concurrency safe because we are the last and only thread to alter this
 * sub-buffer. As long as it is not delivered and read, no other thread can
 * alter the offset, alter the reserve_count or call the
 * client_buffer_end_callback on this sub-buffer.
 *
 * The only remaining threads could be the ones with pending commits. They will
 * have to do the deliver themselves.  Not concurrency safe in overwrite mode.
 * We detect corrupted subbuffers with commit and reserve counts. We keep a
 * corrupted sub-buffers count and push the readers across these sub-buffers.
 *
 * Not concurrency safe if a writer is stalled in a subbuffer and another writer
 * switches in, finding out it's corrupted.  The result will be than the old
 * (uncommited) subbuffer will be declared corrupted, and that the new subbuffer
 * will be declared corrupted too because of the commit count adjustment.
 */
static inline void ltt_reserve_end_switch_current(
		struct ltt_channel_struct *ltt_channel,
		struct ltt_channel_buf_struct *ltt_buf, struct rchan *rchan,
		struct rchan_buf *buf,
		struct ltt_reserve_switch_offsets *offsets, u64 *tsc)
{
	long endidx = SUBBUF_INDEX(offsets->end - 1, rchan);

	ltt_channel->buffer_end(buf, *tsc, offsets->end, endidx);
	/* Must write buffer begin before incrementing commit count */
	smp_wmb();
	offsets->commit_count =
		local_add_return(rchan->subbuf_size
				 - (SUBBUF_OFFSET(offsets->end - 1, rchan)
				 + 1),
				 &ltt_buf->commit_count[endidx]);
	if ((BUFFER_TRUNC(offsets->end - 1, rchan)
			>> ltt_channel->n_subbufs_order)
			- ((offsets->commit_count - rchan->subbuf_size)
				& ltt_channel->commit_count_mask) == 0)
		ltt_deliver(buf, endidx, offsets->commit_count);
}

/**
 * ltt_relay_reserve_slot - Atomic slot reservation in a LTTng buffer.
 * @trace: the trace structure to log to.
 * @ltt_channel: channel structure
 * @transport_data: data structure specific to ltt relay
 * @data_size: size of the variable length data to log.
 * @slot_size: pointer to total size of the slot (out)
 * @buf_offset : pointer to reserved buffer offset (out)
 * @tsc: pointer to the tsc at the slot reservation (out)
 * @cpu: cpuid
 *
 * Return : -ENOSPC if not enough space, else returns 0.
 * It will take care of sub-buffer switching.
 */
static notrace int ltt_relay_reserve_slot(struct ltt_trace_struct *trace,
		struct ltt_channel_struct *ltt_channel, void **transport_data,
		size_t data_size, size_t *slot_size, long *buf_offset, u64 *tsc,
		unsigned int *rflags, int largest_align)
{
	struct rchan *rchan = ltt_channel->trans_channel_data;
	struct rchan_buf *buf = *transport_data = rchan->buf;
	struct ltt_channel_buf_struct *ltt_buf = ltt_channel->buf;
	struct ltt_reserve_switch_offsets offsets;

	offsets.reserve_commit_diff = 0;
	offsets.size = 0;

	/*
	 * Perform retryable operations.
	 */
	if (ltt_nesting > 4) {
		local_inc(&ltt_buf->events_lost);
		return -EPERM;
	}
	do {
		if (ltt_relay_try_reserve(ltt_channel, ltt_buf,
				rchan, buf, &offsets, data_size, tsc, rflags,
				largest_align))
			return -ENOSPC;
	} while (local_cmpxchg(&ltt_buf->offset, offsets.old,
			offsets.end) != offsets.old);

	/*
	 * Atomically update last_tsc. This update races against concurrent
	 * atomic updates, but the race will always cause supplementary full TSC
	 * events, never the opposite (missing a full TSC event when it would be
	 * needed).
	 */
	save_last_tsc(ltt_buf, *tsc);

	/*
	 * Push the reader if necessary
	 */
	ltt_reserve_push_reader(ltt_channel, ltt_buf, rchan, buf, &offsets);

	/*
	 * Switch old subbuffer if needed.
	 */
	if (offsets.end_switch_old)
		ltt_reserve_switch_old_subbuf(ltt_channel, ltt_buf, rchan, buf,
			&offsets, tsc);

	/*
	 * Populate new subbuffer.
	 */
	if (offsets.begin_switch)
		ltt_reserve_switch_new_subbuf(ltt_channel, ltt_buf, rchan,
			buf, &offsets, tsc);

	if (offsets.end_switch_current)
		ltt_reserve_end_switch_current(ltt_channel, ltt_buf, rchan,
			buf, &offsets, tsc);

	*slot_size = offsets.size;
	*buf_offset = offsets.begin + offsets.before_hdr_pad;
	return 0;
}

/*
 * Force a sub-buffer switch for a per-cpu buffer. This operation is
 * completely reentrant : can be called while tracing is active with
 * absolutely no lock held.
 *
 * Note, however, that as a local_cmpxchg is used for some atomic
 * operations, this function must be called from the CPU which owns the buffer
 * for a ACTIVE flush.
 */
static notrace void ltt_force_switch(struct rchan_buf *buf,
		enum force_switch_mode mode)
{
	struct ltt_channel_struct *ltt_channel =
			(struct ltt_channel_struct *)buf->chan->private_data;
	struct ltt_channel_buf_struct *ltt_buf = ltt_channel->buf;
	struct rchan *rchan = ltt_channel->trans_channel_data;
	struct ltt_reserve_switch_offsets offsets;
	u64 tsc;

	offsets.reserve_commit_diff = 0;
	offsets.size = 0;

	/*
	 * Perform retryable operations.
	 */
	do {
		if (ltt_relay_try_switch(mode, ltt_channel, ltt_buf,
				rchan, buf, &offsets, &tsc))
			return;
	} while (local_cmpxchg(&ltt_buf->offset, offsets.old,
			offsets.end) != offsets.old);

	/*
	 * Atomically update last_tsc. This update races against concurrent
	 * atomic updates, but the race will always cause supplementary full TSC
	 * events, never the opposite (missing a full TSC event when it would be
	 * needed).
	 */
	save_last_tsc(ltt_buf, tsc);

	/*
	 * Push the reader if necessary
	 */
	if (mode == FORCE_ACTIVE)
		ltt_reserve_push_reader(ltt_channel, ltt_buf, rchan,
					buf, &offsets);

	/*
	 * Switch old subbuffer if needed.
	 */
	if (offsets.end_switch_old)
		ltt_reserve_switch_old_subbuf(ltt_channel, ltt_buf, rchan, buf,
			&offsets, &tsc);

	/*
	 * Populate new subbuffer.
	 */
	if (mode == FORCE_ACTIVE)
		ltt_reserve_switch_new_subbuf(ltt_channel,
			ltt_buf, rchan, buf, &offsets, &tsc);
}

/*
 * This is called with preemption disabled when user space has requested
 * blocking mode.  If one of the active traces has free space below a
 * specific threshold value, we reenable preemption and block.
 */
static int ltt_relay_user_blocking(struct ltt_trace_struct *trace,
		unsigned int chan_index, size_t data_size,
		struct user_dbg_data *dbg)
{
//ust// 	struct rchan *rchan;
//ust// 	struct ltt_channel_buf_struct *ltt_buf;
//ust// 	struct ltt_channel_struct *channel;
//ust// 	struct rchan_buf *relay_buf;
//ust// 	int cpu;
//ust// 	DECLARE_WAITQUEUE(wait, current);
//ust// 
//ust// 	channel = &trace->channels[chan_index];
//ust// 	rchan = channel->trans_channel_data;
//ust// 	cpu = smp_processor_id();
//ust// 	relay_buf = rchan->buf[cpu];
//ust// 	ltt_buf = percpu_ptr(channel->buf, cpu);
//ust// 
//ust// 	/*
//ust// 	 * Check if data is too big for the channel : do not
//ust// 	 * block for it.
//ust// 	 */
//ust// 	if (LTT_RESERVE_CRITICAL + data_size > relay_buf->chan->subbuf_size)
//ust// 		return 0;
//ust// 
//ust// 	/*
//ust// 	 * If free space too low, we block. We restart from the
//ust// 	 * beginning after we resume (cpu id may have changed
//ust// 	 * while preemption is active).
//ust// 	 */
//ust// 	spin_lock(&ltt_buf->full_lock);
//ust// 	if (!channel->overwrite) {
//ust// 		dbg->write = local_read(&ltt_buf->offset);
//ust// 		dbg->read = atomic_long_read(&ltt_buf->consumed);
//ust// 		dbg->avail_size = dbg->write + LTT_RESERVE_CRITICAL + data_size
//ust// 				  - SUBBUF_TRUNC(dbg->read,
//ust// 						 relay_buf->chan);
//ust// 		if (dbg->avail_size > rchan->alloc_size) {
//ust// 			__set_current_state(TASK_INTERRUPTIBLE);
//ust// 			add_wait_queue(&ltt_buf->write_wait, &wait);
//ust// 			spin_unlock(&ltt_buf->full_lock);
//ust// 			preempt_enable();
//ust// 			schedule();
//ust// 			__set_current_state(TASK_RUNNING);
//ust// 			remove_wait_queue(&ltt_buf->write_wait, &wait);
//ust// 			if (signal_pending(current))
//ust// 				return -ERESTARTSYS;
//ust// 			preempt_disable();
//ust// 			return 1;
//ust// 		}
//ust// 	}
//ust// 	spin_unlock(&ltt_buf->full_lock);
	return 0;
}

static void ltt_relay_print_user_errors(struct ltt_trace_struct *trace,
		unsigned int chan_index, size_t data_size,
		struct user_dbg_data *dbg)
{
	struct rchan *rchan;
	struct ltt_channel_buf_struct *ltt_buf;
	struct ltt_channel_struct *channel;
	struct rchan_buf *relay_buf;

	channel = &trace->channels[chan_index];
	rchan = channel->trans_channel_data;
	relay_buf = rchan->buf;
	ltt_buf = channel->buf;

	printk(KERN_ERR "Error in LTT usertrace : "
	"buffer full : event lost in blocking "
	"mode. Increase LTT_RESERVE_CRITICAL.\n");
	printk(KERN_ERR "LTT nesting level is %u.\n", ltt_nesting);
	printk(KERN_ERR "LTT avail size %lu.\n",
		dbg->avail_size);
	printk(KERN_ERR "avai write : %lu, read : %lu\n",
			dbg->write, dbg->read);

	dbg->write = local_read(&ltt_buf->offset);
	dbg->read = atomic_long_read(&ltt_buf->consumed);

	printk(KERN_ERR "LTT cur size %lu.\n",
		dbg->write + LTT_RESERVE_CRITICAL + data_size
		- SUBBUF_TRUNC(dbg->read, relay_buf->chan));
	printk(KERN_ERR "cur write : %lu, read : %lu\n",
			dbg->write, dbg->read);
}

//ust// static struct ltt_transport ltt_relay_transport = {
//ust// 	.name = "relay",
//ust// 	.owner = THIS_MODULE,
//ust// 	.ops = {
//ust// 		.create_dirs = ltt_relay_create_dirs,
//ust// 		.remove_dirs = ltt_relay_remove_dirs,
//ust// 		.create_channel = ltt_relay_create_channel,
//ust// 		.finish_channel = ltt_relay_finish_channel,
//ust// 		.remove_channel = ltt_relay_remove_channel,
//ust// 		.wakeup_channel = ltt_relay_async_wakeup_chan,
//ust// 		.commit_slot = ltt_relay_commit_slot,
//ust// 		.reserve_slot = ltt_relay_reserve_slot,
//ust// 		.user_blocking = ltt_relay_user_blocking,
//ust// 		.user_errors = ltt_relay_print_user_errors,
//ust// 	},
//ust// };

static struct ltt_transport ust_relay_transport = {
	.name = "ustrelay",
//ust//	.owner = THIS_MODULE,
	.ops = {
		.create_dirs = ltt_relay_create_dirs,
		.remove_dirs = ltt_relay_remove_dirs,
		.create_channel = ltt_relay_create_channel,
		.finish_channel = ltt_relay_finish_channel,
		.remove_channel = ltt_relay_remove_channel,
		.wakeup_channel = ltt_relay_async_wakeup_chan,
//		.commit_slot = ltt_relay_commit_slot,
		.reserve_slot = ltt_relay_reserve_slot,
		.user_blocking = ltt_relay_user_blocking,
		.user_errors = ltt_relay_print_user_errors,
	},
};

//ust// static int __init ltt_relay_init(void)
//ust// {
//ust//	printk(KERN_INFO "LTT : ltt-relay init\n");
//ust//
//ust//	ltt_file_operations = ltt_relay_file_operations;
//ust//	ltt_file_operations.owner = THIS_MODULE;
//ust//	ltt_file_operations.open = ltt_open;
//ust//	ltt_file_operations.release = ltt_release;
//ust//	ltt_file_operations.poll = ltt_poll;
//ust//	ltt_file_operations.splice_read = ltt_relay_file_splice_read,
//ust//	ltt_file_operations.ioctl = ltt_ioctl;
//ust//#ifdef CONFIG_COMPAT
//ust//	ltt_file_operations.compat_ioctl = ltt_compat_ioctl;
//ust//#endif
//ust// 
//ust// 	ltt_transport_register(&ltt_relay_transport);
//ust// 
//ust// 	return 0;
//ust// }

/*
 * for flight recording. must be called after relay_commit.
 * This function decrements de subbuffer's lost_size each time the commit count
 * reaches back the reserve offset (module subbuffer size). It is useful for
 * crash dump.
 */
//ust// #ifdef CONFIG_LTT_VMCORE
static /* inline */ void ltt_write_commit_counter(struct rchan_buf *buf,
		struct ltt_channel_buf_struct *ltt_buf,
		long idx, long buf_offset, long commit_count, size_t data_size)
{
	long offset;
	long commit_seq_old;

	offset = buf_offset + data_size;

	/*
	 * SUBBUF_OFFSET includes commit_count_mask. We can simply
	 * compare the offsets within the subbuffer without caring about
	 * buffer full/empty mismatch because offset is never zero here
	 * (subbuffer header and event headers have non-zero length).
	 */
	if (unlikely(SUBBUF_OFFSET(offset - commit_count, buf->chan)))
		return;

	commit_seq_old = local_read(&ltt_buf->commit_seq[idx]);
	while (commit_seq_old < commit_count)
		commit_seq_old = local_cmpxchg(&ltt_buf->commit_seq[idx],
					 commit_seq_old, commit_count);
}
//ust// #else
//ust// static inline void ltt_write_commit_counter(struct rchan_buf *buf,
//ust// 		long buf_offset, size_t slot_size)
//ust// {
//ust// }
//ust// #endif

/*
 * Atomic unordered slot commit. Increments the commit count in the
 * specified sub-buffer, and delivers it if necessary.
 *
 * Parameters:
 *
 * @ltt_channel : channel structure
 * @transport_data: transport-specific data
 * @buf_offset : offset following the event header.
 * @data_size : size of the event data.
 * @slot_size : size of the reserved slot.
 */
/* FIXME: make this function static inline in the .h! */
/*static*/ /* inline */ notrace void ltt_commit_slot(
		struct ltt_channel_struct *ltt_channel,
		void **transport_data, long buf_offset,
		size_t data_size, size_t slot_size)
{
	struct rchan_buf *buf = *transport_data;
	struct ltt_channel_buf_struct *ltt_buf = ltt_channel->buf;
	struct rchan *rchan = buf->chan;
	long offset_end = buf_offset;
	long endidx = SUBBUF_INDEX(offset_end - 1, rchan);
	long commit_count;

	/* Must write slot data before incrementing commit count */
	smp_wmb();
	commit_count = local_add_return(slot_size,
		&ltt_buf->commit_count[endidx]);
	/* Check if all commits have been done */
	if ((BUFFER_TRUNC(offset_end - 1, rchan)
			>> ltt_channel->n_subbufs_order)
			- ((commit_count - rchan->subbuf_size)
			   & ltt_channel->commit_count_mask) == 0)
		ltt_deliver(buf, endidx, commit_count);
	/*
	 * Update lost_size for each commit. It's needed only for extracting
	 * ltt buffers from vmcore, after crash.
	 */
	ltt_write_commit_counter(buf, ltt_buf, endidx,
				 buf_offset, commit_count, data_size);

	DBG("commited slot. now commit count is %ld", commit_count);
}


static char initialized = 0;

void __attribute__((constructor)) init_ustrelay_transport(void)
{
	if(!initialized) {
		ltt_transport_register(&ust_relay_transport);
		initialized = 1;
	}
}

static void __exit ltt_relay_exit(void)
{
//ust//	printk(KERN_INFO "LTT : ltt-relay exit\n");

	ltt_transport_unregister(&ust_relay_transport);
}

//ust// module_init(ltt_relay_init);
//ust// module_exit(ltt_relay_exit);
//ust// 
//ust// MODULE_LICENSE("GPL");
//ust// MODULE_AUTHOR("Mathieu Desnoyers");
//ust// MODULE_DESCRIPTION("Linux Trace Toolkit Next Generation Lockless Relay");
