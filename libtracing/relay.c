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

#include <linux/time.h>
#include <linux/ltt-tracer.h>
#include <linux/ltt-relay.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/bitops.h>
#include <linux/fs.h>
#include <linux/smp_lock.h>
#include <linux/debugfs.h>
#include <linux/stat.h>
#include <linux/cpu.h>
#include <linux/pipe_fs_i.h>
#include <linux/splice.h>
#include <asm/atomic.h>
#include <asm/local.h>

#if 0
#define printk_dbg(fmt, args...) printk(fmt, args)
#else
#define printk_dbg(fmt, args...)
#endif

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
	wait_queue_head_t write_wait;	/*
					 * Wait queue for blocking user space
					 * writers
					 */
	atomic_t wakeup_readers;	/* Boolean : wakeup readers waiting ? */
} ____cacheline_aligned;

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

static struct file_operations ltt_file_operations;

/*
 * A switch is done during tracing or as a final flush after tracing (so it
 * won't write in the new sub-buffer).
 */
enum force_switch_mode { FORCE_ACTIVE, FORCE_FLUSH };

static int ltt_relay_create_buffer(struct ltt_trace_struct *trace,
		struct ltt_channel_struct *ltt_chan,
		struct rchan_buf *buf,
		unsigned int cpu,
		unsigned int n_subbufs);

static void ltt_relay_destroy_buffer(struct ltt_channel_struct *ltt_chan,
		unsigned int cpu);

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
	struct ltt_channel_buf_struct *ltt_buf =
		percpu_ptr(channel->buf, buf->cpu);
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

static notrace void ltt_deliver(struct rchan_buf *buf, unsigned int subbuf_idx,
		void *subbuf)
{
	struct ltt_channel_struct *channel =
		(struct ltt_channel_struct *)buf->chan->private_data;
	struct ltt_channel_buf_struct *ltt_buf =
		percpu_ptr(channel->buf, buf->cpu);

	atomic_set(&ltt_buf->wakeup_readers, 1);
}

static struct dentry *ltt_create_buf_file_callback(const char *filename,
		struct dentry *parent, int mode,
		struct rchan_buf *buf)
{
	struct ltt_channel_struct *ltt_chan;
	int err;
	struct dentry *dentry;

	ltt_chan = buf->chan->private_data;
	err = ltt_relay_create_buffer(ltt_chan->trace, ltt_chan,
					buf, buf->cpu,
					buf->chan->n_subbufs);
	if (err)
		return ERR_PTR(err);

	dentry = debugfs_create_file(filename, mode, parent, buf,
			&ltt_file_operations);
	if (!dentry)
		goto error;
	return dentry;
error:
	ltt_relay_destroy_buffer(ltt_chan, buf->cpu);
	return NULL;
}

static int ltt_remove_buf_file_callback(struct dentry *dentry)
{
	struct rchan_buf *buf = dentry->d_inode->i_private;
	struct ltt_channel_struct *ltt_chan = buf->chan->private_data;

	debugfs_remove(dentry);
	ltt_relay_destroy_buffer(ltt_chan, buf->cpu);

	return 0;
}

/*
 * Wake writers :
 *
 * This must be done after the trace is removed from the RCU list so that there
 * are no stalled writers.
 */
static void ltt_relay_wake_writers(struct ltt_channel_buf_struct *ltt_buf)
{

	if (waitqueue_active(&ltt_buf->write_wait))
		wake_up_interruptible(&ltt_buf->write_wait);
}

/*
 * This function should not be called from NMI interrupt context
 */
static notrace void ltt_buf_unfull(struct rchan_buf *buf,
		unsigned int subbuf_idx,
		long offset)
{
	struct ltt_channel_struct *ltt_channel =
		(struct ltt_channel_struct *)buf->chan->private_data;
	struct ltt_channel_buf_struct *ltt_buf =
		percpu_ptr(ltt_channel->buf, buf->cpu);

	ltt_relay_wake_writers(ltt_buf);
}

/**
 *	ltt_open - open file op for ltt files
 *	@inode: opened inode
 *	@file: opened file
 *
 *	Open implementation. Makes sure only one open instance of a buffer is
 *	done at a given moment.
 */
static int ltt_open(struct inode *inode, struct file *file)
{
	struct rchan_buf *buf = inode->i_private;
	struct ltt_channel_struct *ltt_channel =
		(struct ltt_channel_struct *)buf->chan->private_data;
	struct ltt_channel_buf_struct *ltt_buf =
		percpu_ptr(ltt_channel->buf, buf->cpu);

	if (!atomic_long_add_unless(&ltt_buf->active_readers, 1, 1))
		return -EBUSY;
	return ltt_relay_file_operations.open(inode, file);
}

/**
 *	ltt_release - release file op for ltt files
 *	@inode: opened inode
 *	@file: opened file
 *
 *	Release implementation.
 */
static int ltt_release(struct inode *inode, struct file *file)
{
	struct rchan_buf *buf = inode->i_private;
	struct ltt_channel_struct *ltt_channel =
		(struct ltt_channel_struct *)buf->chan->private_data;
	struct ltt_channel_buf_struct *ltt_buf =
		percpu_ptr(ltt_channel->buf, buf->cpu);
	int ret;

	WARN_ON(atomic_long_read(&ltt_buf->active_readers) != 1);
	atomic_long_dec(&ltt_buf->active_readers);
	ret = ltt_relay_file_operations.release(inode, file);
	WARN_ON(ret);
	return ret;
}

/**
 *	ltt_poll - file op for ltt files
 *	@filp: the file
 *	@wait: poll table
 *
 *	Poll implementation.
 */
static unsigned int ltt_poll(struct file *filp, poll_table *wait)
{
	unsigned int mask = 0;
	struct inode *inode = filp->f_dentry->d_inode;
	struct rchan_buf *buf = inode->i_private;
	struct ltt_channel_struct *ltt_channel =
		(struct ltt_channel_struct *)buf->chan->private_data;
	struct ltt_channel_buf_struct *ltt_buf =
		percpu_ptr(ltt_channel->buf, buf->cpu);

	if (filp->f_mode & FMODE_READ) {
		poll_wait_set_exclusive(wait);
		poll_wait(filp, &buf->read_wait, wait);

		WARN_ON(atomic_long_read(&ltt_buf->active_readers) != 1);
		if (SUBBUF_TRUNC(local_read(&ltt_buf->offset),
							buf->chan)
		  - SUBBUF_TRUNC(atomic_long_read(&ltt_buf->consumed),
							buf->chan)
		  == 0) {
			if (buf->finalized)
				return POLLHUP;
			else
				return 0;
		} else {
			struct rchan *rchan =
				ltt_channel->trans_channel_data;
			if (SUBBUF_TRUNC(local_read(&ltt_buf->offset),
					buf->chan)
			  - SUBBUF_TRUNC(atomic_long_read(
						&ltt_buf->consumed),
					buf->chan)
			  >= rchan->alloc_size)
				return POLLPRI | POLLRDBAND;
			else
				return POLLIN | POLLRDNORM;
		}
	}
	return mask;
}

static int ltt_do_get_subbuf(struct rchan_buf *buf, struct ltt_channel_buf_struct *ltt_buf, long *pconsumed_old)
{
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

static int ltt_do_put_subbuf(struct rchan_buf *buf, struct ltt_channel_buf_struct *ltt_buf, u32 uconsumed_old)
{
	long consumed_new, consumed_old;

	consumed_old = atomic_long_read(&ltt_buf->consumed);
	consumed_old = consumed_old & (~0xFFFFFFFFL);
	consumed_old = consumed_old | uconsumed_old;
	consumed_new = SUBBUF_ALIGN(consumed_old, buf->chan);

	spin_lock(&ltt_buf->full_lock);
	if (atomic_long_cmpxchg(&ltt_buf->consumed, consumed_old,
				consumed_new)
	    != consumed_old) {
		/* We have been pushed by the writer : the last
		 * buffer read _is_ corrupted! It can also
		 * happen if this is a buffer we never got. */
		spin_unlock(&ltt_buf->full_lock);
		return -EIO;
	} else {
		/* tell the client that buffer is now unfull */
		int index;
		long data;
		index = SUBBUF_INDEX(consumed_old, buf->chan);
		data = BUFFER_OFFSET(consumed_old, buf->chan);
		ltt_buf_unfull(buf, index, data);
		spin_unlock(&ltt_buf->full_lock);
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
static int ltt_ioctl(struct inode *inode, struct file *filp,
		unsigned int cmd, unsigned long arg)
{
	struct rchan_buf *buf = inode->i_private;
	struct ltt_channel_struct *ltt_channel =
		(struct ltt_channel_struct *)buf->chan->private_data;
	struct ltt_channel_buf_struct *ltt_buf =
		percpu_ptr(ltt_channel->buf, buf->cpu);
	u32 __user *argp = (u32 __user *)arg;

	WARN_ON(atomic_long_read(&ltt_buf->active_readers) != 1);
	switch (cmd) {
	case RELAY_GET_SUBBUF:
	{
		int ret;
		ret = ltt_do_get_subbuf(buf, ltt_buf, &consumed_old);
		if(ret < 0)
			return ret;
		return put_user((u32)consumed_old, argp);
	}
	case RELAY_PUT_SUBBUF:
	{
		int ret;
		u32 uconsumed_old;
		ret = get_user(uconsumed_old, argp);
		if (ret)
			return ret; /* will return -EFAULT */
		return ltt_do_put_subbuf(buf, ltt_buf, uconsumed_old);
	}
	case RELAY_GET_N_SUBBUFS:
		return put_user((u32)buf->chan->n_subbufs, argp);
		break;
	case RELAY_GET_SUBBUF_SIZE:
		return put_user((u32)buf->chan->subbuf_size, argp);
		break;
	default:
		return -ENOIOCTLCMD;
	}
	return 0;
}

#ifdef CONFIG_COMPAT
static long ltt_compat_ioctl(struct file *file, unsigned int cmd,
		unsigned long arg)
{
	long ret = -ENOIOCTLCMD;

	lock_kernel();
	ret = ltt_ioctl(file->f_dentry->d_inode, file, cmd, arg);
	unlock_kernel();

	return ret;
}
#endif

static void ltt_relay_pipe_buf_release(struct pipe_inode_info *pipe,
				   struct pipe_buffer *pbuf)
{
}

static struct pipe_buf_operations ltt_relay_pipe_buf_ops = {
	.can_merge = 0,
	.map = generic_pipe_buf_map,
	.unmap = generic_pipe_buf_unmap,
	.confirm = generic_pipe_buf_confirm,
	.release = ltt_relay_pipe_buf_release,
	.steal = generic_pipe_buf_steal,
	.get = generic_pipe_buf_get,
};

static void ltt_relay_page_release(struct splice_pipe_desc *spd, unsigned int i)
{
}

/*
 *	subbuf_splice_actor - splice up to one subbuf's worth of data
 */
static int subbuf_splice_actor(struct file *in,
			       loff_t *ppos,
			       struct pipe_inode_info *pipe,
			       size_t len,
			       unsigned int flags)
{
	struct rchan_buf *buf = in->private_data;
	struct ltt_channel_struct *ltt_channel =
		(struct ltt_channel_struct *)buf->chan->private_data;
	struct ltt_channel_buf_struct *ltt_buf =
		percpu_ptr(ltt_channel->buf, buf->cpu);
	unsigned int poff, subbuf_pages, nr_pages;
	struct page *pages[PIPE_BUFFERS];
	struct partial_page partial[PIPE_BUFFERS];
	struct splice_pipe_desc spd = {
		.pages = pages,
		.nr_pages = 0,
		.partial = partial,
		.flags = flags,
		.ops = &ltt_relay_pipe_buf_ops,
		.spd_release = ltt_relay_page_release,
	};
	long consumed_old, consumed_idx, roffset;
	unsigned long bytes_avail;

	/*
	 * Check that a GET_SUBBUF ioctl has been done before.
	 */
	WARN_ON(atomic_long_read(&ltt_buf->active_readers) != 1);
	consumed_old = atomic_long_read(&ltt_buf->consumed);
	consumed_old += *ppos;
	consumed_idx = SUBBUF_INDEX(consumed_old, buf->chan);

	/*
	 * Adjust read len, if longer than what is available
	 */
	bytes_avail = SUBBUF_TRUNC(local_read(&ltt_buf->offset), buf->chan)
		    - consumed_old;
	WARN_ON(bytes_avail > buf->chan->alloc_size);
	len = min_t(size_t, len, bytes_avail);
	subbuf_pages = bytes_avail >> PAGE_SHIFT;
	nr_pages = min_t(unsigned int, subbuf_pages, PIPE_BUFFERS);
	roffset = consumed_old & PAGE_MASK;
	poff = consumed_old & ~PAGE_MASK;
	printk_dbg(KERN_DEBUG "SPLICE actor len %zu pos %zd write_pos %ld\n",
		len, (ssize_t)*ppos, local_read(&ltt_buf->offset));

	for (; spd.nr_pages < nr_pages; spd.nr_pages++) {
		unsigned int this_len;
		struct buf_page *page;

		if (!len)
			break;
		printk_dbg(KERN_DEBUG "SPLICE actor loop len %zu roffset %ld\n",
			len, roffset);

		this_len = PAGE_SIZE - poff;
		page = ltt_relay_read_get_page(buf, roffset);
		spd.pages[spd.nr_pages] = page->page;
		spd.partial[spd.nr_pages].offset = poff;
		spd.partial[spd.nr_pages].len = this_len;

		poff = 0;
		roffset += PAGE_SIZE;
		len -= this_len;
	}

	if (!spd.nr_pages)
		return 0;

	return splice_to_pipe(pipe, &spd);
}

static ssize_t ltt_relay_file_splice_read(struct file *in,
				      loff_t *ppos,
				      struct pipe_inode_info *pipe,
				      size_t len,
				      unsigned int flags)
{
	ssize_t spliced;
	int ret;

	ret = 0;
	spliced = 0;

	printk_dbg(KERN_DEBUG "SPLICE read len %zu pos %zd\n",
		len, (ssize_t)*ppos);
	while (len && !spliced) {
		ret = subbuf_splice_actor(in, ppos, pipe, len, flags);
		printk_dbg(KERN_DEBUG "SPLICE read loop ret %d\n", ret);
		if (ret < 0)
			break;
		else if (!ret) {
			if (flags & SPLICE_F_NONBLOCK)
				ret = -EAGAIN;
			break;
		}

		*ppos += ret;
		if (ret > len)
			len = 0;
		else
			len -= ret;
		spliced += ret;
	}

	if (spliced)
		return spliced;

	return ret;
}

static void ltt_relay_print_subbuffer_errors(
		struct ltt_channel_struct *ltt_chan,
		long cons_off, unsigned int cpu)
{
	struct rchan *rchan = ltt_chan->trans_channel_data;
	struct ltt_channel_buf_struct *ltt_buf =
		percpu_ptr(ltt_chan->buf, cpu);
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
		"and cons_off : %ld (cpu %u)\n",
		ltt_chan->channel_name, write_offset, cons_off, cpu);
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
		struct ltt_channel_struct *ltt_chan, int cpu)
{
	struct rchan *rchan = ltt_chan->trans_channel_data;
	struct ltt_channel_buf_struct *ltt_buf =
		percpu_ptr(ltt_chan->buf, cpu);
	long cons_off;

	for (cons_off = atomic_long_read(&ltt_buf->consumed);
			(SUBBUF_TRUNC(local_read(&ltt_buf->offset),
				      rchan)
			 - cons_off) > 0;
			cons_off = SUBBUF_ALIGN(cons_off, rchan))
		ltt_relay_print_subbuffer_errors(ltt_chan, cons_off, cpu);
}

static void ltt_relay_print_buffer_errors(struct ltt_channel_struct *ltt_chan,
		unsigned int cpu)
{
	struct ltt_trace_struct *trace = ltt_chan->trace;
	struct ltt_channel_buf_struct *ltt_buf =
		percpu_ptr(ltt_chan->buf, cpu);

	if (local_read(&ltt_buf->events_lost))
		printk(KERN_ALERT
			"LTT : %s : %ld events lost "
			"in %s channel (cpu %u).\n",
			ltt_chan->channel_name,
			local_read(&ltt_buf->events_lost),
			ltt_chan->channel_name, cpu);
	if (local_read(&ltt_buf->corrupted_subbuffers))
		printk(KERN_ALERT
			"LTT : %s : %ld corrupted subbuffers "
			"in %s channel (cpu %u).\n",
			ltt_chan->channel_name,
			local_read(&ltt_buf->corrupted_subbuffers),
			ltt_chan->channel_name, cpu);

	ltt_relay_print_errors(trace, ltt_chan, cpu);
}

static void ltt_relay_remove_dirs(struct ltt_trace_struct *trace)
{
	debugfs_remove(trace->dentry.trace_root);
}

static void ltt_relay_release_channel(struct kref *kref)
{
	struct ltt_channel_struct *ltt_chan = container_of(kref,
			struct ltt_channel_struct, kref);
	percpu_free(ltt_chan->buf);
}

/*
 * Create ltt buffer.
 */
static int ltt_relay_create_buffer(struct ltt_trace_struct *trace,
		struct ltt_channel_struct *ltt_chan, struct rchan_buf *buf,
		unsigned int cpu, unsigned int n_subbufs)
{
	struct ltt_channel_buf_struct *ltt_buf =
		percpu_ptr(ltt_chan->buf, cpu);
	unsigned int j;

	ltt_buf->commit_count =
		kzalloc_node(sizeof(ltt_buf->commit_count) * n_subbufs,
			GFP_KERNEL, cpu_to_node(cpu));
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
	init_waitqueue_head(&ltt_buf->write_wait);
	atomic_set(&ltt_buf->wakeup_readers, 0);
	spin_lock_init(&ltt_buf->full_lock);

	ltt_buffer_begin_callback(buf, trace->start_tsc, 0);
	/* atomic_add made on local variable on data that belongs to
	 * various CPUs : ok because tracing not started (for this cpu). */
	local_add(ltt_subbuffer_header_size(), &ltt_buf->commit_count[0]);

	local_set(&ltt_buf->events_lost, 0);
	local_set(&ltt_buf->corrupted_subbuffers, 0);

	return 0;
}

static void ltt_relay_destroy_buffer(struct ltt_channel_struct *ltt_chan,
		unsigned int cpu)
{
	struct ltt_trace_struct *trace = ltt_chan->trace;
	struct ltt_channel_buf_struct *ltt_buf =
		percpu_ptr(ltt_chan->buf, cpu);

	kref_put(&ltt_chan->trace->ltt_transport_kref,
		ltt_release_transport);
	ltt_relay_print_buffer_errors(ltt_chan, cpu);
	kfree(ltt_buf->commit_count);
	ltt_buf->commit_count = NULL;
	kref_put(&ltt_chan->kref, ltt_relay_release_channel);
	kref_put(&trace->kref, ltt_release_trace);
	wake_up_interruptible(&trace->kref_wq);
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
	ltt_chan->buf = percpu_alloc_mask(sizeof(struct ltt_channel_buf_struct),
					  GFP_KERNEL, cpu_possible_map);
	if (!ltt_chan->buf)
		goto ltt_percpu_alloc_error;
	ltt_chan->trans_channel_data = ltt_relay_open(tmpname,
			dir,
			subbuf_size,
			n_subbufs,
			&trace->callbacks,
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
	percpu_free(ltt_chan->buf);
ltt_percpu_alloc_error:
	err = EPERM;
end:
	kfree(tmpname);
	return err;
}

static int ltt_relay_create_dirs(struct ltt_trace_struct *new_trace)
{
	new_trace->dentry.trace_root = debugfs_create_dir(new_trace->trace_name,
			get_ltt_root());
	if (new_trace->dentry.trace_root == NULL) {
		printk(KERN_ERR "LTT : Trace directory name %s already taken\n",
				new_trace->trace_name);
		return EEXIST;
	}

	new_trace->callbacks.create_buf_file = ltt_create_buf_file_callback;
	new_trace->callbacks.remove_buf_file = ltt_remove_buf_file_callback;

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
	buf->finalized = 1;
	ltt_force_switch(buf, FORCE_FLUSH);
}

static void ltt_relay_async_wakeup_chan(struct ltt_channel_struct *ltt_channel)
{
	unsigned int i;
	struct rchan *rchan = ltt_channel->trans_channel_data;

	for_each_possible_cpu(i) {
		struct ltt_channel_buf_struct *ltt_buf =
			percpu_ptr(ltt_channel->buf, i);

		if (atomic_read(&ltt_buf->wakeup_readers) == 1) {
			atomic_set(&ltt_buf->wakeup_readers, 0);
			wake_up_interruptible(&rchan->buf[i]->read_wait);
		}
	}
}

static void ltt_relay_finish_buffer(struct ltt_channel_struct *ltt_channel,
		unsigned int cpu)
{
	struct rchan *rchan = ltt_channel->trans_channel_data;

	if (rchan->buf[cpu]) {
		struct ltt_channel_buf_struct *ltt_buf =
			percpu_ptr(ltt_channel->buf, cpu);
		ltt_relay_buffer_flush(rchan->buf[cpu]);
		ltt_relay_wake_writers(ltt_buf);
	}
}


static void ltt_relay_finish_channel(struct ltt_channel_struct *ltt_channel)
{
	unsigned int i;

	for_each_possible_cpu(i)
		ltt_relay_finish_buffer(ltt_channel, i);
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
		ltt_deliver(buf, oldidx, NULL);
}

/*
 * ltt_reserve_switch_new_subbuf: Populate new subbuffer.
 *
 * This code can be executed unordered : writers may already have written to the
 * sub-buffer before this code gets executed, caution.  The commit makes sure
 * that this code is executed before the deliver of this sub-buffer.
 */
static inline void ltt_reserve_switch_new_subbuf(
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
		ltt_deliver(buf, beginidx, NULL);
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
		ltt_deliver(buf, endidx, NULL);
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
		unsigned int *rflags, int largest_align, int cpu)
{
	struct rchan *rchan = ltt_channel->trans_channel_data;
	struct rchan_buf *buf = *transport_data =
			rchan->buf[cpu];
	struct ltt_channel_buf_struct *ltt_buf =
			percpu_ptr(ltt_channel->buf, buf->cpu);
	struct ltt_reserve_switch_offsets offsets;

	offsets.reserve_commit_diff = 0;
	offsets.size = 0;

	/*
	 * Perform retryable operations.
	 */
	if (__get_cpu_var(ltt_nesting) > 4) {
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
	struct ltt_channel_buf_struct *ltt_buf =
			percpu_ptr(ltt_channel->buf, buf->cpu);
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
 * for flight recording. must be called after relay_commit.
 * This function decrements de subbuffer's lost_size each time the commit count
 * reaches back the reserve offset (module subbuffer size). It is useful for
 * crash dump.
 * We use slot_size - 1 to make sure we deal correctly with the case where we
 * fill the subbuffer completely (so the subbuf index stays in the previous
 * subbuffer).
 */
#ifdef CONFIG_LTT_VMCORE
static inline void ltt_write_commit_counter(struct rchan_buf *buf,
		long buf_offset, size_t slot_size)
{
	struct ltt_channel_struct *ltt_channel =
		(struct ltt_channel_struct *)buf->chan->private_data;
	struct ltt_channel_buf_struct *ltt_buf =
			percpu_ptr(ltt_channel->buf, buf->cpu);
	struct ltt_subbuffer_header *header;
	long offset, subbuf_idx, commit_count;
	uint32_t lost_old, lost_new;

	subbuf_idx = SUBBUF_INDEX(buf_offset - 1, buf->chan);
	offset = buf_offset + slot_size;
	header = (struct ltt_subbuffer_header *)
			ltt_relay_offset_address(buf,
				subbuf_idx * buf->chan->subbuf_size);
	for (;;) {
		lost_old = header->lost_size;
		commit_count =
			local_read(&ltt_buf->commit_count[subbuf_idx]);
		/* SUBBUF_OFFSET includes commit_count_mask */
		if (!SUBBUF_OFFSET(offset - commit_count, buf->chan)) {
			lost_new = (uint32_t)buf->chan->subbuf_size
				   - SUBBUF_OFFSET(commit_count, buf->chan);
			lost_old = cmpxchg_local(&header->lost_size, lost_old,
						lost_new);
			if (lost_old <= lost_new)
				break;
		} else {
			break;
		}
	}
}
#else
static inline void ltt_write_commit_counter(struct rchan_buf *buf,
		long buf_offset, size_t slot_size)
{
}
#endif

/*
 * Atomic unordered slot commit. Increments the commit count in the
 * specified sub-buffer, and delivers it if necessary.
 *
 * Parameters:
 *
 * @ltt_channel : channel structure
 * @transport_data: transport-specific data
 * @buf_offset : offset following the event header.
 * @slot_size : size of the reserved slot.
 */
static notrace void ltt_relay_commit_slot(
		struct ltt_channel_struct *ltt_channel,
		void **transport_data, long buf_offset, size_t slot_size)
{
	struct rchan_buf *buf = *transport_data;
	struct ltt_channel_buf_struct *ltt_buf =
			percpu_ptr(ltt_channel->buf, buf->cpu);
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
		ltt_deliver(buf, endidx, NULL);
	/*
	 * Update lost_size for each commit. It's needed only for extracting
	 * ltt buffers from vmcore, after crash.
	 */
	ltt_write_commit_counter(buf, buf_offset, slot_size);
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
	struct rchan *rchan;
	struct ltt_channel_buf_struct *ltt_buf;
	struct ltt_channel_struct *channel;
	struct rchan_buf *relay_buf;
	int cpu;
	DECLARE_WAITQUEUE(wait, current);

	channel = &trace->channels[chan_index];
	rchan = channel->trans_channel_data;
	cpu = smp_processor_id();
	relay_buf = rchan->buf[cpu];
	ltt_buf = percpu_ptr(channel->buf, cpu);

	/*
	 * Check if data is too big for the channel : do not
	 * block for it.
	 */
	if (LTT_RESERVE_CRITICAL + data_size > relay_buf->chan->subbuf_size)
		return 0;

	/*
	 * If free space too low, we block. We restart from the
	 * beginning after we resume (cpu id may have changed
	 * while preemption is active).
	 */
	spin_lock(&ltt_buf->full_lock);
	if (!channel->overwrite) {
		dbg->write = local_read(&ltt_buf->offset);
		dbg->read = atomic_long_read(&ltt_buf->consumed);
		dbg->avail_size = dbg->write + LTT_RESERVE_CRITICAL + data_size
				  - SUBBUF_TRUNC(dbg->read,
						 relay_buf->chan);
		if (dbg->avail_size > rchan->alloc_size) {
			__set_current_state(TASK_INTERRUPTIBLE);
			add_wait_queue(&ltt_buf->write_wait, &wait);
			spin_unlock(&ltt_buf->full_lock);
			preempt_enable();
			schedule();
			__set_current_state(TASK_RUNNING);
			remove_wait_queue(&ltt_buf->write_wait, &wait);
			if (signal_pending(current))
				return -ERESTARTSYS;
			preempt_disable();
			return 1;
		}
	}
	spin_unlock(&ltt_buf->full_lock);
	return 0;
}

static void ltt_relay_print_user_errors(struct ltt_trace_struct *trace,
		unsigned int chan_index, size_t data_size,
		struct user_dbg_data *dbg, int cpu)
{
	struct rchan *rchan;
	struct ltt_channel_buf_struct *ltt_buf;
	struct ltt_channel_struct *channel;
	struct rchan_buf *relay_buf;

	channel = &trace->channels[chan_index];
	rchan = channel->trans_channel_data;
	relay_buf = rchan->buf[cpu];
	ltt_buf = percpu_ptr(channel->buf, cpu);

	printk(KERN_ERR "Error in LTT usertrace : "
	"buffer full : event lost in blocking "
	"mode. Increase LTT_RESERVE_CRITICAL.\n");
	printk(KERN_ERR "LTT nesting level is %u.\n",
		per_cpu(ltt_nesting, cpu));
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

static struct ltt_transport ltt_relay_transport = {
	.name = "relay",
	.owner = THIS_MODULE,
	.ops = {
		.create_dirs = ltt_relay_create_dirs,
		.remove_dirs = ltt_relay_remove_dirs,
		.create_channel = ltt_relay_create_channel,
		.finish_channel = ltt_relay_finish_channel,
		.remove_channel = ltt_relay_remove_channel,
		.wakeup_channel = ltt_relay_async_wakeup_chan,
		.commit_slot = ltt_relay_commit_slot,
		.reserve_slot = ltt_relay_reserve_slot,
		.user_blocking = ltt_relay_user_blocking,
		.user_errors = ltt_relay_print_user_errors,
	},
};

static int __init ltt_relay_init(void)
{
	printk(KERN_INFO "LTT : ltt-relay init\n");

	ltt_file_operations = ltt_relay_file_operations;
	ltt_file_operations.owner = THIS_MODULE;
	ltt_file_operations.open = ltt_open;
	ltt_file_operations.release = ltt_release;
	ltt_file_operations.poll = ltt_poll;
	ltt_file_operations.splice_read = ltt_relay_file_splice_read,
	ltt_file_operations.ioctl = ltt_ioctl;
#ifdef CONFIG_COMPAT
	ltt_file_operations.compat_ioctl = ltt_compat_ioctl;
#endif

	ltt_transport_register(&ltt_relay_transport);

	return 0;
}

static void __exit ltt_relay_exit(void)
{
	printk(KERN_INFO "LTT : ltt-relay exit\n");

	ltt_transport_unregister(&ltt_relay_transport);
}

module_init(ltt_relay_init);
module_exit(ltt_relay_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mathieu Desnoyers");
MODULE_DESCRIPTION("Linux Trace Toolkit Next Generation Lockless Relay");
