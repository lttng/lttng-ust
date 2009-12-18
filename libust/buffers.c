/*
 * buffers.c
 * LTTng userspace tracer buffering system
 *
 * Copyright (C) 2009 - Pierre-Marc Fournier (pierre-marc dot fournier at polymtl dot ca)
 * Copyright (C) 2008 - Mathieu Desnoyers (mathieu.desnoyers@polymtl.ca)
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

#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <fcntl.h>
#include <ust/kernelcompat.h>
#include <kcompat/kref.h>
#include "buffers.h"
#include "channels.h"
#include "tracer.h"
#include "tracercore.h"
#include "usterr.h"

static DEFINE_MUTEX(ust_buffers_channels_mutex);
static LIST_HEAD(ust_buffers_channels);

static int ust_buffers_init_buffer(struct ltt_trace_struct *trace,
		struct ust_channel *ltt_chan,
		struct ust_buffer *buf,
		unsigned int n_subbufs);

static int ust_buffers_alloc_buf(struct ust_buffer *buf, size_t *size)
{
	void *ptr;
	int result;

	*size = PAGE_ALIGN(*size);

	result = buf->shmid = shmget(getpid(), *size, IPC_CREAT | IPC_EXCL | 0700);
	if(result == -1 && errno == EINVAL) {
		ERR("shmget() returned EINVAL; maybe /proc/sys/kernel/shmmax should be increased.");
		return -1;
	}
	else if(result == -1) {
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

static struct ust_buffer *ust_buffers_create_buf(struct ust_channel *channel)
{
	int result;

	result = ust_buffers_alloc_buf(channel->buf, &channel->alloc_size);
	if(result)
		goto free_buf;

	((struct ust_buffer *)channel->buf)->chan = channel;
	kref_get(&channel->kref);
	return channel->buf;

free_buf:
	return NULL;
}

static void ust_buffers_destroy_channel(struct kref *kref)
{
	struct ust_channel *chan = container_of(kref, struct ust_channel, kref);
	free(chan);
}

static void ust_buffers_destroy_buf(struct ust_buffer *buf)
{
	struct ust_channel *chan = buf->chan;
	int result;

	result = munmap(buf->buf_data, buf->buf_size);
	if(result == -1) {
		PERROR("munmap");
	}

	free(buf);
	kref_put(&chan->kref, ust_buffers_destroy_channel);
}

/* called from kref_put */
static void ust_buffers_remove_buf(struct kref *kref)
{
	struct ust_buffer *buf = container_of(kref, struct ust_buffer, kref);
	ust_buffers_destroy_buf(buf);
}

static struct ust_buffer *ust_buffers_open_buf(struct ust_channel *chan)
{
	struct ust_buffer *buf = NULL;
	int err;

	buf = ust_buffers_create_buf(chan);
	if (!buf)
		return NULL;

	kref_init(&buf->kref);

	err = ust_buffers_init_buffer(chan->trace, chan, buf, chan->subbuf_cnt);

	if (err)
		return ERR_PTR(err);

	return buf;

	/* FIXME: decrementally destroy on error? */
}

/**
 *	ust_buffers_close_buf - close a channel buffer
 *	@buf: buffer
 */
static void ust_buffers_close_buf(struct ust_buffer *buf)
{
	kref_put(&buf->kref, ust_buffers_remove_buf);
}

int ust_buffers_channel_open(struct ust_channel *chan, size_t subbuf_size, size_t subbuf_cnt)
{
	if(subbuf_size == 0 || subbuf_cnt == 0)
		return -1;

	chan->version = UST_CHANNEL_VERSION;
	chan->subbuf_cnt = subbuf_cnt;
	chan->subbuf_size = subbuf_size;
	chan->subbuf_size_order = get_count_order(subbuf_size);
	chan->alloc_size = FIX_SIZE(subbuf_size * subbuf_cnt);
	kref_init(&chan->kref);

	mutex_lock(&ust_buffers_channels_mutex);
	chan->buf = ust_buffers_open_buf(chan);
	if (!chan->buf)
		goto error;
	list_add(&chan->list, &ust_buffers_channels);
	mutex_unlock(&ust_buffers_channels_mutex);

	return 0;

	error:
	kref_put(&chan->kref, ust_buffers_destroy_channel);
	mutex_unlock(&ust_buffers_channels_mutex);
	return -1;
}

void ust_buffers_channel_close(struct ust_channel *chan)
{
	if (!chan)
		return;

	mutex_lock(&ust_buffers_channels_mutex);
	if (chan->buf)
		ust_buffers_close_buf(chan->buf);

	list_del(&chan->list);
	kref_put(&chan->kref, ust_buffers_destroy_channel);
	mutex_unlock(&ust_buffers_channels_mutex);
}

/* _ust_buffers_write()
 *
 * @buf: destination buffer
 * @offset: offset in destination
 * @src: source buffer
 * @len: length of source
 * @cpy: already copied
 */

void _ust_buffers_write(struct ust_buffer *buf, size_t offset,
	const void *src, size_t len, ssize_t cpy)
{
	do {
		len -= cpy;
		src += cpy;
		offset += cpy;
		WARN_ON(offset >= buf->buf_size);

		cpy = min_t(size_t, len, buf->buf_size - offset);
		ust_buffers_do_copy(buf->buf_data + offset, src, cpy);
	} while (unlikely(len != cpy));
}

/**
 * ltt_buffers_offset_address - get address of a location within the buffer
 * @buf : buffer
 * @offset : offset within the buffer.
 *
 * Return the address where a given offset is located.
 * Should be used to get the current subbuffer header pointer. Given we know
 * it's never on a page boundary, it's safe to write directly to this address,
 * as long as the write is never bigger than a page size.
 */
void *ltt_buffers_offset_address(struct ust_buffer *buf, size_t offset)
{
	return ((char *)buf->buf_data)+offset;
}

/*
 * -------
 */

/*
 * Last TSC comparison functions. Check if the current TSC overflows
 * LTT_TSC_BITS bits from the last TSC read. Reads and writes last_tsc
 * atomically.
 */

/* FIXME: does this test work properly? */
#if (BITS_PER_LONG == 32)
static inline void save_last_tsc(struct ust_buffer *ltt_buf,
					u64 tsc)
{
	ltt_buf->last_tsc = (unsigned long)(tsc >> LTT_TSC_BITS);
}

static inline int last_tsc_overflow(struct ust_buffer *ltt_buf,
					u64 tsc)
{
	unsigned long tsc_shifted = (unsigned long)(tsc >> LTT_TSC_BITS);

	if (unlikely((tsc_shifted - ltt_buf->last_tsc)))
		return 1;
	else
		return 0;
}
#else
static inline void save_last_tsc(struct ust_buffer *ltt_buf,
					u64 tsc)
{
	ltt_buf->last_tsc = (unsigned long)tsc;
}

static inline int last_tsc_overflow(struct ust_buffer *ltt_buf,
					u64 tsc)
{
	if (unlikely((tsc - ltt_buf->last_tsc) >> LTT_TSC_BITS))
		return 1;
	else
		return 0;
}
#endif

/*
 * A switch is done during tracing or as a final flush after tracing (so it
 * won't write in the new sub-buffer).
 */
enum force_switch_mode { FORCE_ACTIVE, FORCE_FLUSH };

static void ust_buffers_destroy_buffer(struct ust_channel *ltt_chan);

static void ltt_force_switch(struct ust_buffer *buf,
		enum force_switch_mode mode);

/*
 * Trace callbacks
 */
static void ltt_buffer_begin_callback(struct ust_buffer *buf,
			u64 tsc, unsigned int subbuf_idx)
{
	struct ust_channel *channel = buf->chan;
	struct ltt_subbuffer_header *header =
		(struct ltt_subbuffer_header *)
			ltt_buffers_offset_address(buf,
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
static notrace void ltt_buffer_end_callback(struct ust_buffer *buf,
		u64 tsc, unsigned int offset, unsigned int subbuf_idx)
{
	struct ltt_subbuffer_header *header =
		(struct ltt_subbuffer_header *)
			ltt_buffers_offset_address(buf,
				subbuf_idx * buf->chan->subbuf_size);

	header->lost_size = SUBBUF_OFFSET((buf->chan->subbuf_size - offset),
				buf->chan);
	header->cycle_count_end = tsc;
	header->events_lost = local_read(&buf->events_lost);
	header->subbuf_corrupt = local_read(&buf->corrupted_subbuffers);

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

static notrace void ltt_deliver(struct ust_buffer *buf, unsigned int subbuf_idx,
		long commit_count)
{
	int result;

//ust// #ifdef CONFIG_LTT_VMCORE
	local_set(&buf->commit_seq[subbuf_idx], commit_count);
//ust// #endif

	/* wakeup consumer */
	result = write(buf->data_ready_fd_write, "1", 1);
	if(result == -1) {
		PERROR("write (in ltt_relay_buffer_flush)");
		ERR("this should never happen!");
	}
//ust//	atomic_set(&ltt_buf->wakeup_readers, 1);
}

/*
 * This function should not be called from NMI interrupt context
 */
static notrace void ltt_buf_unfull(struct ust_buffer *buf,
		unsigned int subbuf_idx,
		long offset)
{
//ust//	struct ltt_channel_struct *ltt_channel =
//ust//		(struct ltt_channel_struct *)buf->chan->private_data;
//ust//	struct ltt_channel_buf_struct *ltt_buf = ltt_channel->buf;
//ust//
//ust//	ltt_relay_wake_writers(ltt_buf);
}

int ust_buffers_do_get_subbuf(struct ust_buffer *buf, long *pconsumed_old)
{
	struct ust_channel *channel = buf->chan;
	long consumed_old, consumed_idx, commit_count, write_offset;
	consumed_old = atomic_long_read(&buf->consumed);
	consumed_idx = SUBBUF_INDEX(consumed_old, buf->chan);
	commit_count = local_read(&buf->commit_count[consumed_idx]);
	/*
	 * Make sure we read the commit count before reading the buffer
	 * data and the write offset. Correct consumed offset ordering
	 * wrt commit count is insured by the use of cmpxchg to update
	 * the consumed offset.
	 */
	smp_rmb();
	write_offset = local_read(&buf->offset);
	/*
	 * Check that the subbuffer we are trying to consume has been
	 * already fully committed.
	 */
	if (((commit_count - buf->chan->subbuf_size)
	     & channel->commit_count_mask)
	    - (BUFFER_TRUNC(consumed_old, buf->chan)
	       >> channel->n_subbufs_order)
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

int ust_buffers_do_put_subbuf(struct ust_buffer *buf, u32 uconsumed_old)
{
	long consumed_new, consumed_old;

	consumed_old = atomic_long_read(&buf->consumed);
	consumed_old = consumed_old & (~0xFFFFFFFFL);
	consumed_old = consumed_old | uconsumed_old;
	consumed_new = SUBBUF_ALIGN(consumed_old, buf->chan);

//ust//	spin_lock(&ltt_buf->full_lock);
	if (atomic_long_cmpxchg(&buf->consumed, consumed_old,
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

static void ltt_relay_print_subbuffer_errors(
		struct ust_channel *channel,
		long cons_off)
{
	struct ust_buffer *ltt_buf = channel->buf;
	long cons_idx, commit_count, write_offset;

	cons_idx = SUBBUF_INDEX(cons_off, channel);
	commit_count = local_read(&ltt_buf->commit_count[cons_idx]);
	/*
	 * No need to order commit_count and write_offset reads because we
	 * execute after trace is stopped when there are no readers left.
	 */
	write_offset = local_read(&ltt_buf->offset);
	WARN( "LTT : unread channel %s offset is %ld "
		"and cons_off : %ld\n",
		channel->channel_name, write_offset, cons_off);
	/* Check each sub-buffer for non filled commit count */
	if (((commit_count - channel->subbuf_size) & channel->commit_count_mask)
	    - (BUFFER_TRUNC(cons_off, channel) >> channel->n_subbufs_order) != 0) {
		ERR("LTT : %s : subbuffer %lu has non filled "
			"commit count %lu.\n",
			channel->channel_name, cons_idx, commit_count);
	}
	ERR("LTT : %s : commit count : %lu, subbuf size %zd\n",
			channel->channel_name, commit_count,
			channel->subbuf_size);
}

static void ltt_relay_print_errors(struct ltt_trace_struct *trace,
		struct ust_channel *channel)
{
	struct ust_buffer *ltt_buf = channel->buf;
	long cons_off;

	/*
	 * Can be called in the error path of allocation when
	 * trans_channel_data is not yet set.
	 */
	if (!channel)
	        return;

	for (cons_off = atomic_long_read(&ltt_buf->consumed);
			(SUBBUF_TRUNC(local_read(&ltt_buf->offset),
				      channel)
			 - cons_off) > 0;
			cons_off = SUBBUF_ALIGN(cons_off, channel))
		ltt_relay_print_subbuffer_errors(channel, cons_off);
}

static void ltt_relay_print_buffer_errors(struct ust_channel *channel)
{
	struct ltt_trace_struct *trace = channel->trace;
	struct ust_buffer *ltt_buf = channel->buf;

	if (local_read(&ltt_buf->events_lost))
		printk(KERN_ALERT
			"LTT : %s : %ld events lost "
			"in %s channel.\n",
			channel->channel_name,
			local_read(&ltt_buf->events_lost),
			channel->channel_name);
	if (local_read(&ltt_buf->corrupted_subbuffers))
		printk(KERN_ALERT
			"LTT : %s : %ld corrupted subbuffers "
			"in %s channel.\n",
			channel->channel_name,
			local_read(&ltt_buf->corrupted_subbuffers),
			channel->channel_name);

	ltt_relay_print_errors(trace, channel);
}

static void ltt_relay_release_channel(struct kref *kref)
{
	struct ust_channel *ltt_chan = container_of(kref,
			struct ust_channel, kref);
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

static int ust_buffers_init_buffer(struct ltt_trace_struct *trace,
		struct ust_channel *ltt_chan, struct ust_buffer *buf,
		unsigned int n_subbufs)
{
	unsigned int j;
	int fds[2];
	int result;

	buf->commit_count =
		zmalloc(sizeof(buf->commit_count) * n_subbufs);
	if (!buf->commit_count)
		return -ENOMEM;
	kref_get(&trace->kref);
	kref_get(&trace->ltt_transport_kref);
	kref_get(&ltt_chan->kref);
	local_set(&buf->offset, ltt_subbuffer_header_size());
	atomic_long_set(&buf->consumed, 0);
	atomic_long_set(&buf->active_readers, 0);
	for (j = 0; j < n_subbufs; j++)
		local_set(&buf->commit_count[j], 0);
//ust//	init_waitqueue_head(&buf->write_wait);
//ust//	atomic_set(&buf->wakeup_readers, 0);
//ust//	spin_lock_init(&buf->full_lock);

	ltt_buffer_begin_callback(buf, trace->start_tsc, 0);

	local_add(ltt_subbuffer_header_size(), &buf->commit_count[0]);

	local_set(&buf->events_lost, 0);
	local_set(&buf->corrupted_subbuffers, 0);

	result = pipe(fds);
	if(result == -1) {
		PERROR("pipe");
		return -1;
	}
	buf->data_ready_fd_read = fds[0];
	buf->data_ready_fd_write = fds[1];

	/* FIXME: do we actually need this? */
	result = fcntl(fds[0], F_SETFL, O_NONBLOCK);
	if(result == -1) {
		PERROR("fcntl");
	}

//ust//	buf->commit_seq = malloc(sizeof(buf->commit_seq) * n_subbufs);
//ust//	if(!ltt_buf->commit_seq) {
//ust//		return -1;
//ust//	}

	/* FIXME: decrementally destroy on error */

	return 0;
}

/* FIXME: use this function */
static void ust_buffers_destroy_buffer(struct ust_channel *ltt_chan)
{
	struct ltt_trace_struct *trace = ltt_chan->trace;
	struct ust_buffer *ltt_buf = ltt_chan->buf;

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

static void ltt_chan_alloc_ltt_buf(struct ust_channel *chan)
{
	void *ptr;
	int result;

	/* Get one page */
	/* FIXME: increase size if we have a seq_commit array that overflows the page */
	size_t size = PAGE_ALIGN(1);

	result = chan->buf_shmid = shmget(getpid(), size, IPC_CREAT | IPC_EXCL | 0700);
	if(chan->buf_shmid == -1) {
		PERROR("shmget");
		return;
	}

	ptr = shmat(chan->buf_shmid, NULL, 0);
	if(ptr == (void *) -1) {
		perror("shmat");
		goto destroy_shmem;
	}

	/* Already mark the shared memory for destruction. This will occur only
         * when all users have detached.
	 */
	result = shmctl(chan->buf_shmid, IPC_RMID, NULL);
	if(result == -1) {
		perror("shmctl");
		return;
	}

	chan->buf = ptr;

	return;

	destroy_shmem:
	result = shmctl(chan->buf_shmid, IPC_RMID, NULL);
	if(result == -1) {
		perror("shmctl");
	}

	return;
}

/*
 * Create channel.
 */
static int ust_buffers_create_channel(const char *trace_name, struct ltt_trace_struct *trace,
	const char *channel_name, struct ust_channel *ltt_chan,
	unsigned int subbuf_size, unsigned int n_subbufs, int overwrite)
{
	int err = 0;
	int result;

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
	/* FIXME: handle error of this call */
	result = ust_buffers_channel_open(ltt_chan, subbuf_size, n_subbufs);
	if (result == -1) {
		printk(KERN_ERR "LTT : Can't open channel for trace %s\n",
				trace_name);
		goto relay_open_error;
	}

	err = 0;
	goto end;

relay_open_error:
//ust//	percpu_free(ltt_chan->buf);
alloc_error:
	err = EPERM;
end:
	return err;
}

/*
 * LTTng channel flush function.
 *
 * Must be called when no tracing is active in the channel, because of
 * accesses across CPUs.
 */
static notrace void ltt_relay_buffer_flush(struct ust_buffer *buf)
{
	int result;

//ust//	buf->finalized = 1;
	ltt_force_switch(buf, FORCE_FLUSH);

	result = write(buf->data_ready_fd_write, "1", 1);
	if(result == -1) {
		PERROR("write (in ltt_relay_buffer_flush)");
		ERR("this should never happen!");
	}
}

static void ltt_relay_async_wakeup_chan(struct ust_channel *ltt_channel)
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

static void ltt_relay_finish_buffer(struct ust_channel *channel)
{
//	int result;

	if (channel->buf) {
		struct ust_buffer *buf = channel->buf;
		ltt_relay_buffer_flush(buf);
//ust//		ltt_relay_wake_writers(ltt_buf);
		/* closing the pipe tells the consumer the buffer is finished */
		
		//result = write(ltt_buf->data_ready_fd_write, "D", 1);
		//if(result == -1) {
		//	PERROR("write (in ltt_relay_finish_buffer)");
		//	ERR("this should never happen!");
		//}
		close(buf->data_ready_fd_write);
	}
}


static void ltt_relay_finish_channel(struct ust_channel *channel)
{
//ust//	unsigned int i;

//ust//	for_each_possible_cpu(i)
		ltt_relay_finish_buffer(channel);
}

static void ltt_relay_remove_channel(struct ust_channel *channel)
{
	ust_buffers_channel_close(channel);
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
		struct ust_channel *channel, struct ust_buffer *buf,
		struct ltt_reserve_switch_offsets *offsets, size_t data_size,
		u64 *tsc, unsigned int *rflags, int largest_align)
{
	offsets->begin = local_read(&buf->offset);
	offsets->old = offsets->begin;
	offsets->begin_switch = 0;
	offsets->end_switch_current = 0;
	offsets->end_switch_old = 0;

	*tsc = trace_clock_read64();
	if (last_tsc_overflow(buf, *tsc))
		*rflags = LTT_RFLAG_ID_SIZE_TSC;

	if (SUBBUF_OFFSET(offsets->begin, buf->chan) == 0) {
		offsets->begin_switch = 1;		/* For offsets->begin */
	} else {
		offsets->size = ust_get_header_size(channel,
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
			 >> channel->n_subbufs_order)
			- (local_read(&buf->commit_count[subbuf_index])
				& channel->commit_count_mask);
		if (offsets->reserve_commit_diff == 0) {
			long consumed;

			consumed = atomic_long_read(&buf->consumed);

			/* Next buffer not corrupted. */
			if (!channel->overwrite &&
				(SUBBUF_TRUNC(offsets->begin, buf->chan)
				 - SUBBUF_TRUNC(consumed, buf->chan))
				>= channel->alloc_size) {

				long consumed_idx = SUBBUF_INDEX(consumed, buf->chan);
				long commit_count = local_read(&buf->commit_count[consumed_idx]);
				if(((commit_count - buf->chan->subbuf_size) & channel->commit_count_mask) - (BUFFER_TRUNC(consumed, buf->chan) >> channel->n_subbufs_order) != 0) {
					WARN("Event dropped. Caused by non-committed event.");
				}
				else {
					WARN("Event dropped. Caused by non-consumed buffer.");
				}
				/*
				 * We do not overwrite non consumed buffers
				 * and we are full : event is lost.
				 */
				local_inc(&buf->events_lost);
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
		offsets->size = ust_get_header_size(channel,
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
			local_inc(&buf->events_lost);
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
		struct ust_channel *channel,
		struct ust_buffer *buf,
		struct ltt_reserve_switch_offsets *offsets,
		u64 *tsc)
{
	long subbuf_index;

	offsets->begin = local_read(&buf->offset);
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
		 >> channel->n_subbufs_order)
		- (local_read(&buf->commit_count[subbuf_index])
			& channel->commit_count_mask);
	if (offsets->reserve_commit_diff == 0) {
		/* Next buffer not corrupted. */
		if (mode == FORCE_ACTIVE
		    && !channel->overwrite
		    && offsets->begin - atomic_long_read(&buf->consumed)
		       >= channel->alloc_size) {
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
		struct ust_channel *channel,
		struct ust_buffer *buf,
		struct ltt_reserve_switch_offsets *offsets)
{
	long consumed_old, consumed_new;

	do {
		consumed_old = atomic_long_read(&buf->consumed);
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
		   >= channel->alloc_size)
			consumed_new = SUBBUF_ALIGN(consumed_old, buf->chan);
		else {
			consumed_new = consumed_old;
			break;
		}
	} while (atomic_long_cmpxchg(&buf->consumed, consumed_old,
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
				  &buf->commit_count[
					SUBBUF_INDEX(offsets->begin,
						     buf->chan)]);
			if (!channel->overwrite
			    || offsets->reserve_commit_diff
			       != channel->subbuf_size) {
				/*
				 * The reserve commit diff was not subbuf_size :
				 * it means the subbuffer was partly written to
				 * and is therefore corrupted. If it is multiple
				 * of subbuffer size and we are in flight
				 * recorder mode, we are skipping over a whole
				 * subbuffer.
				 */
				local_inc(&buf->corrupted_subbuffers);
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
		struct ust_channel *channel,
		struct ust_buffer *buf,
		struct ltt_reserve_switch_offsets *offsets, u64 *tsc)
{
	long oldidx = SUBBUF_INDEX(offsets->old - 1, channel);

	channel->buffer_end(buf, *tsc, offsets->old, oldidx);
	/* Must write buffer end before incrementing commit count */
	smp_wmb();
	offsets->commit_count =
		local_add_return(channel->subbuf_size
				 - (SUBBUF_OFFSET(offsets->old - 1, channel)
				 + 1),
				 &buf->commit_count[oldidx]);
	if ((BUFFER_TRUNC(offsets->old - 1, channel)
			>> channel->n_subbufs_order)
			- ((offsets->commit_count - channel->subbuf_size)
				& channel->commit_count_mask) == 0)
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
		struct ust_channel *channel,
		struct ust_buffer *buf,
		struct ltt_reserve_switch_offsets *offsets, u64 *tsc)
{
	long beginidx = SUBBUF_INDEX(offsets->begin, channel);

	channel->buffer_begin(buf, *tsc, beginidx);
	/* Must write buffer end before incrementing commit count */
	smp_wmb();
	offsets->commit_count = local_add_return(ltt_subbuffer_header_size(),
			&buf->commit_count[beginidx]);
	/* Check if the written buffer has to be delivered */
	if ((BUFFER_TRUNC(offsets->begin, channel)
			>> channel->n_subbufs_order)
			- ((offsets->commit_count - channel->subbuf_size)
				& channel->commit_count_mask) == 0)
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
		struct ust_channel *channel,
		struct ust_buffer *buf,
		struct ltt_reserve_switch_offsets *offsets, u64 *tsc)
{
	long endidx = SUBBUF_INDEX(offsets->end - 1, channel);

	channel->buffer_end(buf, *tsc, offsets->end, endidx);
	/* Must write buffer begin before incrementing commit count */
	smp_wmb();
	offsets->commit_count =
		local_add_return(channel->subbuf_size
				 - (SUBBUF_OFFSET(offsets->end - 1, channel)
				 + 1),
				 &buf->commit_count[endidx]);
	if ((BUFFER_TRUNC(offsets->end - 1, channel)
			>> channel->n_subbufs_order)
			- ((offsets->commit_count - channel->subbuf_size)
				& channel->commit_count_mask) == 0)
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
		struct ust_channel *channel, void **transport_data,
		size_t data_size, size_t *slot_size, long *buf_offset, u64 *tsc,
		unsigned int *rflags, int largest_align)
{
	struct ust_buffer *buf = *transport_data = channel->buf;
	struct ltt_reserve_switch_offsets offsets;

	offsets.reserve_commit_diff = 0;
	offsets.size = 0;

	/*
	 * Perform retryable operations.
	 */
	if (ltt_nesting > 4) {
		local_inc(&buf->events_lost);
		return -EPERM;
	}
	do {
		if (ltt_relay_try_reserve(channel, buf, &offsets, data_size, tsc, rflags,
				largest_align))
			return -ENOSPC;
	} while (local_cmpxchg(&buf->offset, offsets.old,
			offsets.end) != offsets.old);

	/*
	 * Atomically update last_tsc. This update races against concurrent
	 * atomic updates, but the race will always cause supplementary full TSC
	 * events, never the opposite (missing a full TSC event when it would be
	 * needed).
	 */
	save_last_tsc(buf, *tsc);

	/*
	 * Push the reader if necessary
	 */
	ltt_reserve_push_reader(channel, buf, &offsets);

	/*
	 * Switch old subbuffer if needed.
	 */
	if (offsets.end_switch_old)
		ltt_reserve_switch_old_subbuf(channel, buf, &offsets, tsc);

	/*
	 * Populate new subbuffer.
	 */
	if (offsets.begin_switch)
		ltt_reserve_switch_new_subbuf(channel, buf, &offsets, tsc);

	if (offsets.end_switch_current)
		ltt_reserve_end_switch_current(channel, buf, &offsets, tsc);

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
static notrace void ltt_force_switch(struct ust_buffer *buf,
		enum force_switch_mode mode)
{
	struct ust_channel *channel = buf->chan;
	struct ltt_reserve_switch_offsets offsets;
	u64 tsc;

	offsets.reserve_commit_diff = 0;
	offsets.size = 0;

	/*
	 * Perform retryable operations.
	 */
	do {
		if (ltt_relay_try_switch(mode, channel, buf, &offsets, &tsc))
			return;
	} while (local_cmpxchg(&buf->offset, offsets.old,
			offsets.end) != offsets.old);

	/*
	 * Atomically update last_tsc. This update races against concurrent
	 * atomic updates, but the race will always cause supplementary full TSC
	 * events, never the opposite (missing a full TSC event when it would be
	 * needed).
	 */
	save_last_tsc(buf, tsc);

	/*
	 * Push the reader if necessary
	 */
	if (mode == FORCE_ACTIVE)
		ltt_reserve_push_reader(channel, buf, &offsets);

	/*
	 * Switch old subbuffer if needed.
	 */
	if (offsets.end_switch_old)
		ltt_reserve_switch_old_subbuf(channel, buf, &offsets, &tsc);

	/*
	 * Populate new subbuffer.
	 */
	if (mode == FORCE_ACTIVE)
		ltt_reserve_switch_new_subbuf(channel, buf, &offsets, &tsc);
}

static void ltt_relay_print_user_errors(struct ltt_trace_struct *trace,
		unsigned int chan_index, size_t data_size,
		struct user_dbg_data *dbg)
{
	struct ust_channel *channel;
	struct ust_buffer *buf;

	channel = &trace->channels[chan_index];
	buf = channel->buf;

	printk(KERN_ERR "Error in LTT usertrace : "
	"buffer full : event lost in blocking "
	"mode. Increase LTT_RESERVE_CRITICAL.\n");
	printk(KERN_ERR "LTT nesting level is %u.\n", ltt_nesting);
	printk(KERN_ERR "LTT avail size %lu.\n",
		dbg->avail_size);
	printk(KERN_ERR "avai write : %lu, read : %lu\n",
			dbg->write, dbg->read);

	dbg->write = local_read(&buf->offset);
	dbg->read = atomic_long_read(&buf->consumed);

	printk(KERN_ERR "LTT cur size %lu.\n",
		dbg->write + LTT_RESERVE_CRITICAL + data_size
		- SUBBUF_TRUNC(dbg->read, channel));
	printk(KERN_ERR "cur write : %lu, read : %lu\n",
			dbg->write, dbg->read);
}

static struct ltt_transport ust_relay_transport = {
	.name = "ustrelay",
	.ops = {
		.create_channel = ust_buffers_create_channel,
		.finish_channel = ltt_relay_finish_channel,
		.remove_channel = ltt_relay_remove_channel,
		.wakeup_channel = ltt_relay_async_wakeup_chan,
//		.commit_slot = ltt_relay_commit_slot,
		.reserve_slot = ltt_relay_reserve_slot,
		.user_errors = ltt_relay_print_user_errors,
	},
};

/*
 * for flight recording. must be called after relay_commit.
 * This function decrements de subbuffer's lost_size each time the commit count
 * reaches back the reserve offset (module subbuffer size). It is useful for
 * crash dump.
 */
static /* inline */ void ltt_write_commit_counter(struct ust_buffer *buf,
		struct ust_buffer *ltt_buf,
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
		struct ust_channel *channel,
		void **transport_data, long buf_offset,
		size_t data_size, size_t slot_size)
{
	struct ust_buffer *buf = *transport_data;
	long offset_end = buf_offset;
	long endidx = SUBBUF_INDEX(offset_end - 1, channel);
	long commit_count;

	/* Must write slot data before incrementing commit count */
	smp_wmb();
	commit_count = local_add_return(slot_size,
		&buf->commit_count[endidx]);
	/* Check if all commits have been done */
	if ((BUFFER_TRUNC(offset_end - 1, channel)
			>> channel->n_subbufs_order)
			- ((commit_count - channel->subbuf_size)
			   & channel->commit_count_mask) == 0)
		ltt_deliver(buf, endidx, commit_count);
	/*
	 * Update lost_size for each commit. It's needed only for extracting
	 * ltt buffers from vmcore, after crash.
	 */
	ltt_write_commit_counter(buf, buf, endidx,
				 buf_offset, commit_count, data_size);
}


static char initialized = 0;

void __attribute__((constructor)) init_ustrelay_transport(void)
{
	if(!initialized) {
		ltt_transport_register(&ust_relay_transport);
		initialized = 1;
	}
}

static void __attribute__((destructor)) ltt_relay_exit(void)
{
	ltt_transport_unregister(&ust_relay_transport);
}
