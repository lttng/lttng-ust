/*
 * linux/include/linux/ltt-relay.h
 *
 * Copyright (C) 2002, 2003 - Tom Zanussi (zanussi@us.ibm.com), IBM Corp
 * Copyright (C) 1999, 2000, 2001, 2002 - Karim Yaghmour (karim@opersys.com)
 * Copyright (C) 2008 - Mathieu Desnoyers (mathieu.desnoyers@polymtl.ca)
 *
 * CONFIG_RELAY definitions and declarations
 */

#ifndef _LINUX_LTT_RELAY_H
#define _LINUX_LTT_RELAY_H

//ust// #include <linux/types.h>
//ust// #include <linux/sched.h>
//ust// #include <linux/timer.h>
//ust// #include <linux/wait.h>
//ust// #include <linux/list.h>
//ust// #include <linux/fs.h>
//ust// #include <linux/poll.h>
//ust// #include <linux/kref.h>
//ust// #include <linux/mm.h>
//ust// #include <linux/ltt-core.h>
#include "kref.h"
#include "list.h"

/* Needs a _much_ better name... */
#define FIX_SIZE(x) ((((x) - 1) & PAGE_MASK) + PAGE_SIZE)

/*
 * Tracks changes to rchan/rchan_buf structs
 */
#define LTT_RELAY_CHANNEL_VERSION		8

struct rchan_buf;

struct buf_page {
	struct page *page;
	struct rchan_buf *buf;	/* buffer the page belongs to */
	size_t offset;		/* page offset in the buffer */
	struct list_head list;	/* buffer linked list */
};

/*
 * Per-cpu relay channel buffer
 */
struct rchan_buf { 
	struct rchan *chan;             /* associated channel */ 
//ust//	wait_queue_head_t read_wait;    /* reader wait queue */ 
//ust//	struct timer_list timer;        /* reader wake-up timer */ 
//ust//	struct dentry *dentry;          /* channel file dentry */ 
	struct kref kref;               /* channel buffer refcount */ 
//ust//	struct list_head pages;         /* list of buffer pages */ 
	void *buf_data; //ust//
	size_t buf_size;
//ust//	struct buf_page *wpage;         /* current write page (cache) */ 
//ust//	struct buf_page *hpage[2];      /* current subbuf header page (cache) */ 
//ust//	struct buf_page *rpage;         /* current subbuf read page (cache) */ 
//ust//	unsigned int page_count;        /* number of current buffer pages */ 
	unsigned int finalized;         /* buffer has been finalized */ 
//ust//	unsigned int cpu;               /* this buf's cpu */ 
} ____cacheline_aligned; 

/*
 * Relay channel data structure
 */
struct rchan {
	u32 version;			/* the version of this struct */
	size_t subbuf_size;		/* sub-buffer size */
	size_t n_subbufs;		/* number of sub-buffers per buffer */
	size_t alloc_size;		/* total buffer size allocated */
	struct rchan_callbacks *cb;	/* client callbacks */
	struct kref kref;		/* channel refcount */
	void *private_data;		/* for user-defined data */
//ust//	struct rchan_buf *buf[NR_CPUS]; /* per-cpu channel buffers */
	struct rchan_buf *buf;
	struct list_head list;		/* for channel list */
	struct dentry *parent;		/* parent dentry passed to open */
	int subbuf_size_order;		/* order of sub-buffer size */
//ust//	char base_filename[NAME_MAX];	/* saved base filename */
};

/*
 * Relay channel client callbacks
 */
struct rchan_callbacks {
	/*
	 * subbuf_start - called on buffer-switch to a new sub-buffer
	 * @buf: the channel buffer containing the new sub-buffer
	 * @subbuf: the start of the new sub-buffer
	 * @prev_subbuf: the start of the previous sub-buffer
	 * @prev_padding: unused space at the end of previous sub-buffer
	 *
	 * The client should return 1 to continue logging, 0 to stop
	 * logging.
	 *
	 * NOTE: subbuf_start will also be invoked when the buffer is
	 *       created, so that the first sub-buffer can be initialized
	 *       if necessary.  In this case, prev_subbuf will be NULL.
	 *
	 * NOTE: the client can reserve bytes at the beginning of the new
	 *       sub-buffer by calling subbuf_start_reserve() in this callback.
	 */
	int (*subbuf_start) (struct rchan_buf *buf,
			     void *subbuf,
			     void *prev_subbuf,
			     size_t prev_padding);

	/*
	 * create_buf_file - create file to represent a relay channel buffer
	 * @filename: the name of the file to create
	 * @parent: the parent of the file to create
	 * @mode: the mode of the file to create
	 * @buf: the channel buffer
	 *
	 * Called during relay_open(), once for each per-cpu buffer,
	 * to allow the client to create a file to be used to
	 * represent the corresponding channel buffer.  If the file is
	 * created outside of relay, the parent must also exist in
	 * that filesystem.
	 *
	 * The callback should return the dentry of the file created
	 * to represent the relay buffer.
	 *
	 * Setting the is_global outparam to a non-zero value will
	 * cause relay_open() to create a single global buffer rather
	 * than the default set of per-cpu buffers.
	 *
	 * See Documentation/filesystems/relayfs.txt for more info.
	 */
	struct dentry *(*create_buf_file)(const char *filename,
					  struct dentry *parent,
					  int mode,
					  struct rchan_buf *buf);

	/*
	 * remove_buf_file - remove file representing a relay channel buffer
	 * @dentry: the dentry of the file to remove
	 *
	 * Called during relay_close(), once for each per-cpu buffer,
	 * to allow the client to remove a file used to represent a
	 * channel buffer.
	 *
	 * The callback should return 0 if successful, negative if not.
	 */
	int (*remove_buf_file)(struct rchan_buf *buf);
};

extern struct buf_page *ltt_relay_find_prev_page(struct rchan_buf *buf,
	struct buf_page *page, size_t offset, ssize_t diff_offset);

extern struct buf_page *ltt_relay_find_next_page(struct rchan_buf *buf,
	struct buf_page *page, size_t offset, ssize_t diff_offset);

extern void _ltt_relay_write(struct rchan_buf *buf, size_t offset,
	const void *src, size_t len, ssize_t cpy);

extern int ltt_relay_read(struct rchan_buf *buf, size_t offset,
	void *dest, size_t len);

extern struct buf_page *ltt_relay_read_get_page(struct rchan_buf *buf,
	size_t offset);

/*
 * Return the address where a given offset is located.
 * Should be used to get the current subbuffer header pointer. Given we know
 * it's never on a page boundary, it's safe to write directly to this address,
 * as long as the write is never bigger than a page size.
 */
extern void *ltt_relay_offset_address(struct rchan_buf *buf,
	size_t offset);

/*
 * Find the page containing "offset". Cache it if it is after the currently
 * cached page.
 */
static inline struct buf_page *ltt_relay_cache_page(struct rchan_buf *buf,
		struct buf_page **page_cache,
		struct buf_page *page, size_t offset)
{
	ssize_t diff_offset;
	ssize_t half_buf_size = buf->chan->alloc_size >> 1;

	/*
	 * Make sure this is the page we want to write into. The current
	 * page is changed concurrently by other writers. [wrh]page are
	 * used as a cache remembering the last page written
	 * to/read/looked up for header address. No synchronization;
	 * could have to find the previous page is a nested write
	 * occured. Finding the right page is done by comparing the
	 * dest_offset with the buf_page offsets.
	 * When at the exact opposite of the buffer, bias towards forward search
	 * because it will be cached.
	 */

	diff_offset = (ssize_t)offset - (ssize_t)page->offset;
	if (diff_offset <= -(ssize_t)half_buf_size)
		diff_offset += buf->chan->alloc_size;
	else if (diff_offset > half_buf_size)
		diff_offset -= buf->chan->alloc_size;

	if (unlikely(diff_offset >= (ssize_t)PAGE_SIZE)) {
		page = ltt_relay_find_next_page(buf, page, offset, diff_offset);
		*page_cache = page;
	} else if (unlikely(diff_offset < 0)) {
		page = ltt_relay_find_prev_page(buf, page, offset, diff_offset);
	}
	return page;
}

//ust// #ifdef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
 static inline void ltt_relay_do_copy(void *dest, const void *src, size_t len)
{
	switch (len) {
	case 0:	break;
	case 1:	*(u8 *)dest = *(const u8 *)src;
		break;
	case 2:	*(u16 *)dest = *(const u16 *)src;
		break;
	case 4:	*(u32 *)dest = *(const u32 *)src;
		break;
//ust// #if (BITS_PER_LONG == 64)
	case 8:	*(u64 *)dest = *(const u64 *)src;
		break;
//ust// #endif
	default:
		memcpy(dest, src, len);
	}
}
//ust// #else
//ust// /*
//ust//  * Returns whether the dest and src addresses are aligned on
//ust//  * min(sizeof(void *), len). Call this with statically known len for efficiency.
//ust//  */
//ust// static inline int addr_aligned(const void *dest, const void *src, size_t len)
//ust// {
//ust// 	if (ltt_align((size_t)dest, len))
//ust// 		return 0;
//ust// 	if (ltt_align((size_t)src, len))
//ust// 		return 0;
//ust// 	return 1;
//ust// }
//ust// 
//ust// static inline void ltt_relay_do_copy(void *dest, const void *src, size_t len)
//ust// {
//ust// 	switch (len) {
//ust// 	case 0:	break;
//ust// 	case 1:	*(u8 *)dest = *(const u8 *)src;
//ust// 		break;
//ust// 	case 2:	if (unlikely(!addr_aligned(dest, src, 2)))
//ust// 			goto memcpy_fallback;
//ust// 		*(u16 *)dest = *(const u16 *)src;
//ust// 		break;
//ust// 	case 4:	if (unlikely(!addr_aligned(dest, src, 4)))
//ust// 			goto memcpy_fallback;
//ust// 		*(u32 *)dest = *(const u32 *)src;
//ust// 		break;
//ust// #if (BITS_PER_LONG == 64)
//ust// 	case 8:	if (unlikely(!addr_aligned(dest, src, 8)))
//ust// 			goto memcpy_fallback;
//ust// 		*(u64 *)dest = *(const u64 *)src;
//ust// 		break;
//ust// #endif
//ust// 	default:
//ust// 		goto memcpy_fallback;
//ust// 	}
//ust// 	return;
//ust// memcpy_fallback:
//ust// 	memcpy(dest, src, len);
//ust// }
//ust// #endif

static inline int ltt_relay_write(struct rchan_buf *buf, size_t offset,
	const void *src, size_t len)
{
//ust//	struct buf_page *page;
//ust//	ssize_t pagecpy;
//ust//
//ust//	offset &= buf->chan->alloc_size - 1;
//ust//	page = buf->wpage;
//ust//
//ust//	page = ltt_relay_cache_page(buf, &buf->wpage, page, offset);
//ust//	pagecpy = min_t(size_t, len, PAGE_SIZE - (offset & ~PAGE_MASK));
//ust//	ltt_relay_do_copy(page_address(page->page)
//ust//		+ (offset & ~PAGE_MASK), src, pagecpy);
//ust//
//ust//	if (unlikely(len != pagecpy))
//ust//		_ltt_relay_write(buf, offset, src, len, page, pagecpy);
//ust//	return len;


	size_t cpy;
	cpy = min_t(size_t, len, buf->buf_size - offset);
	ltt_relay_do_copy(buf->buf_data + offset, src, cpy);
	
	if (unlikely(len != cpy))
		_ltt_relay_write(buf, offset, src, len, cpy);
	return len;
}

/*
 * CONFIG_LTT_RELAY kernel API, ltt/ltt-relay-alloc.c
 */

struct rchan *ltt_relay_open(const char *base_filename,
			 struct dentry *parent,
			 size_t subbuf_size,
			 size_t n_subbufs,
			 void *private_data);
extern void ltt_relay_close(struct rchan *chan);

/*
 * exported ltt_relay file operations, ltt/ltt-relay-alloc.c
 */
extern const struct file_operations ltt_relay_file_operations;


/* LTTng lockless logging buffer info */
struct ltt_channel_buf_struct {
	/* First 32 bytes cache-hot cacheline */
	local_t offset;			/* Current offset in the buffer */
	local_t *commit_count;		/* Commit count per sub-buffer */
	atomic_long_t consumed;		/*
					 * Current offset in the buffer
					 * standard atomic access (shared)
					 */
	unsigned long last_tsc;		/*
					 * Last timestamp written in the buffer.
					 */
	/* End of first 32 bytes cacheline */
	atomic_long_t active_readers;	/*
					 * Active readers count
					 * standard atomic access (shared)
					 */
	local_t events_lost;
	local_t corrupted_subbuffers;
	spinlock_t full_lock;		/*
					 * buffer full condition spinlock, only
					 * for userspace tracing blocking mode
					 * synchronization with reader.
					 */
//ust//	wait_queue_head_t write_wait;	/*
//ust//					 * Wait queue for blocking user space
//ust//					 * writers
//ust//					 */
	atomic_t wakeup_readers;	/* Boolean : wakeup readers waiting ? */
} ____cacheline_aligned;

int ltt_do_get_subbuf(struct rchan_buf *buf, struct ltt_channel_buf_struct *ltt_buf, long *pconsumed_old);

int ltt_do_put_subbuf(struct rchan_buf *buf, struct ltt_channel_buf_struct *ltt_buf, u32 uconsumed_old);


#endif /* _LINUX_LTT_RELAY_H */

