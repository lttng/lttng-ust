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

#include <unistd.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <fcntl.h>
#include <stdlib.h>

#include <ust/clock.h>

#include "buffers.h"
#include "channels.h"
#include "tracer.h"
#include "tracercore.h"
#include "usterr.h"

struct ltt_reserve_switch_offsets {
	long begin, end, old;
	long begin_switch, end_switch_current, end_switch_old;
	size_t before_hdr_pad, size;
};


static DEFINE_MUTEX(ust_buffers_channels_mutex);
static CDS_LIST_HEAD(ust_buffers_channels);

static int get_n_cpus(void)
{
	int result;
	static int n_cpus = 0;

	if(!n_cpus) {
		/* On Linux, when some processors are offline
		 * _SC_NPROCESSORS_CONF counts the offline
		 * processors, whereas _SC_NPROCESSORS_ONLN
		 * does not. If we used _SC_NPROCESSORS_ONLN,
		 * getcpu() could return a value greater than
		 * this sysconf, in which case the arrays
		 * indexed by processor would overflow.
		 */
		result = sysconf(_SC_NPROCESSORS_CONF);
		if(result == -1) {
			return -1;
		}

		n_cpus = result;
	}

	return n_cpus;
}

/**
 * _ust_buffers_strncpy_fixup - Fix an incomplete string in a ltt_relay buffer.
 * @buf : buffer
 * @offset : offset within the buffer
 * @len : length to write
 * @copied: string actually copied
 * @terminated: does string end with \0
 *
 * Fills string with "X" if incomplete.
 */
void _ust_buffers_strncpy_fixup(struct ust_buffer *buf, size_t offset,
				size_t len, size_t copied, int terminated)
{
	size_t buf_offset, cpy;

	if (copied == len) {
		/*
		 * Deal with non-terminated string.
		 */
		assert(!terminated);
		offset += copied - 1;
		buf_offset = BUFFER_OFFSET(offset, buf->chan);
		/*
		 * Underlying layer should never ask for writes across
		 * subbuffers.
		 */
		assert(buf_offset
		       < buf->chan->subbuf_size*buf->chan->subbuf_cnt);
		ust_buffers_do_memset(buf->buf_data + buf_offset, '\0', 1);
		return;
	}

	/*
	 * Deal with incomplete string.
	 * Overwrite string's \0 with X too.
	 */
	cpy = copied - 1;
	assert(terminated);
	len -= cpy;
	offset += cpy;
	buf_offset = BUFFER_OFFSET(offset, buf->chan);

	/*
	 * Underlying layer should never ask for writes across subbuffers.
	 */
	assert(buf_offset
	       < buf->chan->subbuf_size*buf->chan->subbuf_cnt);

	ust_buffers_do_memset(buf->buf_data + buf_offset,
			      'X', len);

	/*
	 * Overwrite last 'X' with '\0'.
	 */
	offset += len - 1;
	buf_offset = BUFFER_OFFSET(offset, buf->chan);
	/*
	 * Underlying layer should never ask for writes across subbuffers.
	 */
	assert(buf_offset
	       < buf->chan->subbuf_size*buf->chan->subbuf_cnt);
	ust_buffers_do_memset(buf->buf_data + buf_offset, '\0', 1);
}

static int ust_buffers_init_buffer(struct ust_trace *trace,
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

	/* FIXME: should have matching call to shmdt */
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

int ust_buffers_create_buf(struct ust_channel *channel, int cpu)
{
	int result;
	struct ust_buffer *buf = channel->buf[cpu];

	buf->cpu = cpu;
	result = ust_buffers_alloc_buf(buf, &channel->alloc_size);
	if(result)
		return -1;

	buf->chan = channel;
	kref_get(&channel->kref);
	return 0;
}

static void ust_buffers_destroy_channel(struct kref *kref)
{
	struct ust_channel *chan = _ust_container_of(kref, struct ust_channel, kref);
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

//ust//	chan->buf[buf->cpu] = NULL;
	free(buf);
	kref_put(&chan->kref, ust_buffers_destroy_channel);
}

/* called from kref_put */
static void ust_buffers_remove_buf(struct kref *kref)
{
	struct ust_buffer *buf = _ust_container_of(kref, struct ust_buffer, kref);
	ust_buffers_destroy_buf(buf);
}

int ust_buffers_open_buf(struct ust_channel *chan, int cpu)
{
	int result;

	result = ust_buffers_create_buf(chan, cpu);
	if (result == -1)
		return -1;

	kref_init(&chan->buf[cpu]->kref);

	result = ust_buffers_init_buffer(chan->trace, chan, chan->buf[cpu], chan->subbuf_cnt);
	if(result == -1)
		return -1;

	return 0;

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
	int i;
	int result;

	if(subbuf_size == 0 || subbuf_cnt == 0)
		return -1;

	/* Check that the subbuffer size is larger than a page. */
	WARN_ON_ONCE(subbuf_size < PAGE_SIZE);

	/*
	 * Make sure the number of subbuffers and subbuffer size are power of 2.
	 */
	WARN_ON_ONCE(hweight32(subbuf_size) != 1);
	WARN_ON(hweight32(subbuf_cnt) != 1);

	chan->version = UST_CHANNEL_VERSION;
	chan->subbuf_cnt = subbuf_cnt;
	chan->subbuf_size = subbuf_size;
	chan->subbuf_size_order = get_count_order(subbuf_size);
	chan->alloc_size = subbuf_size * subbuf_cnt;

	kref_init(&chan->kref);

	pthread_mutex_lock(&ust_buffers_channels_mutex);
	for(i=0; i<chan->n_cpus; i++) {
		result = ust_buffers_open_buf(chan, i);
		if (result == -1)
			goto error;
	}
	cds_list_add(&chan->list, &ust_buffers_channels);
	pthread_mutex_unlock(&ust_buffers_channels_mutex);

	return 0;

	/* Jump directly inside the loop to close the buffers that were already
	 * opened. */
	for(; i>=0; i--) {
		ust_buffers_close_buf(chan->buf[i]);
error:
		do {} while(0);
	}

	kref_put(&chan->kref, ust_buffers_destroy_channel);
	pthread_mutex_unlock(&ust_buffers_channels_mutex);
	return -1;
}

void ust_buffers_channel_close(struct ust_channel *chan)
{
	int i;
	if(!chan)
		return;

	pthread_mutex_lock(&ust_buffers_channels_mutex);
	for(i=0; i<chan->n_cpus; i++) {
	/* FIXME: if we make it here, then all buffers were necessarily allocated. Moreover, we don't
	 * initialize to NULL so we cannot use this check. Should we? */
//ust//		if (chan->buf[i])
			ust_buffers_close_buf(chan->buf[i]);
	}

	cds_list_del(&chan->list);
	kref_put(&chan->kref, ust_buffers_destroy_channel);
	pthread_mutex_unlock(&ust_buffers_channels_mutex);
}

/*
 * -------
 */

static void ust_buffers_destroy_buffer(struct ust_channel *ltt_chan, int cpu);

static void ltt_force_switch(struct ust_buffer *buf,
		enum force_switch_mode mode);

/*
 * Trace callbacks
 */
static void ltt_buffer_begin(struct ust_buffer *buf,
			u64 tsc, unsigned int subbuf_idx)
{
	struct ust_channel *channel = buf->chan;
	struct ltt_subbuffer_header *header =
		(struct ltt_subbuffer_header *)
			ust_buffers_offset_address(buf,
				subbuf_idx * buf->chan->subbuf_size);

	header->cycle_count_begin = tsc;
	header->data_size = 0xFFFFFFFF; /* for recognizing crashed buffers */
	header->sb_size = 0xFFFFFFFF; /* for recognizing crashed buffers */
	/* FIXME: add memory cmm_barrier? */
	ltt_write_trace_header(channel->trace, header);
}

/*
 * offset is assumed to never be 0 here : never deliver a completely empty
 * subbuffer. The lost size is between 0 and subbuf_size-1.
 */
static notrace void ltt_buffer_end(struct ust_buffer *buf,
		u64 tsc, unsigned int offset, unsigned int subbuf_idx)
{
	struct ltt_subbuffer_header *header =
		(struct ltt_subbuffer_header *)
			ust_buffers_offset_address(buf,
				subbuf_idx * buf->chan->subbuf_size);
	u32 data_size = SUBBUF_OFFSET(offset - 1, buf->chan) + 1;

	header->data_size = data_size;
	header->sb_size = PAGE_ALIGN(data_size);
	header->cycle_count_end = tsc;
	header->events_lost = uatomic_read(&buf->events_lost);
	header->subbuf_corrupt = uatomic_read(&buf->corrupted_subbuffers);
	if(unlikely(header->events_lost > 0)) {
		DBG("Some events (%d) were lost in %s_%d", header->events_lost, buf->chan->channel_name, buf->cpu);
	}
}

/*
 * This function should not be called from NMI interrupt context
 */
static notrace void ltt_buf_unfull(struct ust_buffer *buf,
		unsigned int subbuf_idx,
		long offset)
{
}

/*
 * Promote compiler cmm_barrier to a smp_mb().
 * For the specific LTTng case, this IPI call should be removed if the
 * architecture does not reorder writes.  This should eventually be provided by
 * a separate architecture-specific infrastructure.
 */
//ust// static void remote_mb(void *info)
//ust// {
//ust// 	smp_mb();
//ust// }

int ust_buffers_get_subbuf(struct ust_buffer *buf, long *consumed)
{
	struct ust_channel *channel = buf->chan;
	long consumed_old, consumed_idx, commit_count, write_offset;
//ust//	int retval;

	consumed_old = uatomic_read(&buf->consumed);
	consumed_idx = SUBBUF_INDEX(consumed_old, buf->chan);
	commit_count = uatomic_read(&buf->commit_count[consumed_idx].cc_sb);
	/*
	 * Make sure we read the commit count before reading the buffer
	 * data and the write offset. Correct consumed offset ordering
	 * wrt commit count is insured by the use of cmpxchg to update
	 * the consumed offset.
	 * smp_call_function_single can fail if the remote CPU is offline,
	 * this is OK because then there is no wmb to execute there.
	 * If our thread is executing on the same CPU as the on the buffers
	 * belongs to, we don't have to synchronize it at all. If we are
	 * migrated, the scheduler will take care of the memory cmm_barriers.
	 * Normally, smp_call_function_single() should ensure program order when
	 * executing the remote function, which implies that it surrounds the
	 * function execution with :
	 * smp_mb()
	 * send IPI
	 * csd_lock_wait
	 *                recv IPI
	 *                smp_mb()
	 *                exec. function
	 *                smp_mb()
	 *                csd unlock
	 * smp_mb()
	 *
	 * However, smp_call_function_single() does not seem to clearly execute
	 * such cmm_barriers. It depends on spinlock semantic to provide the cmm_barrier
	 * before executing the IPI and, when busy-looping, csd_lock_wait only
	 * executes smp_mb() when it has to wait for the other CPU.
	 *
	 * I don't trust this code. Therefore, let's add the smp_mb() sequence
	 * required ourself, even if duplicated. It has no performance impact
	 * anyway.
	 *
	 * smp_mb() is needed because cmm_smp_rmb() and cmm_smp_wmb() only order read vs
	 * read and write vs write. They do not ensure core synchronization. We
	 * really have to ensure total order between the 3 cmm_barriers running on
	 * the 2 CPUs.
	 */
//ust// #ifdef LTT_NO_IPI_BARRIER
	/*
	 * Local rmb to match the remote wmb to read the commit count before the
	 * buffer data and the write offset.
	 */
	cmm_smp_rmb();
//ust// #else
//ust// 	if (raw_smp_processor_id() != buf->cpu) {
//ust// 		smp_mb();	/* Total order with IPI handler smp_mb() */
//ust// 		smp_call_function_single(buf->cpu, remote_mb, NULL, 1);
//ust// 		smp_mb();	/* Total order with IPI handler smp_mb() */
//ust// 	}
//ust// #endif

	write_offset = uatomic_read(&buf->offset);
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

	/* FIXME: is this ok to disable the reading feature? */
//ust//	retval = update_read_sb_index(buf, consumed_idx);
//ust//	if (retval)
//ust//		return retval;

	*consumed = consumed_old;

	return 0;
}

int ust_buffers_put_subbuf(struct ust_buffer *buf, unsigned long uconsumed_old)
{
	long consumed_new, consumed_old;

	consumed_old = uatomic_read(&buf->consumed);
	consumed_old = consumed_old & (~0xFFFFFFFFL);
	consumed_old = consumed_old | uconsumed_old;
	consumed_new = SUBBUF_ALIGN(consumed_old, buf->chan);

//ust//	spin_lock(&ltt_buf->full_lock);
	if (uatomic_cmpxchg(&buf->consumed, consumed_old,
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
		long cons_off, int cpu)
{
	struct ust_buffer *ltt_buf = channel->buf[cpu];
	long cons_idx, commit_count, commit_count_sb, write_offset;

	cons_idx = SUBBUF_INDEX(cons_off, channel);
	commit_count = uatomic_read(&ltt_buf->commit_count[cons_idx].cc);
	commit_count_sb = uatomic_read(&ltt_buf->commit_count[cons_idx].cc_sb);

	/*
	 * No need to order commit_count and write_offset reads because we
	 * execute after trace is stopped when there are no readers left.
	 */
	write_offset = uatomic_read(&ltt_buf->offset);
	WARN( "LTT : unread channel %s offset is %ld "
		"and cons_off : %ld (cpu %d)\n",
		channel->channel_name, write_offset, cons_off, cpu);
	/* Check each sub-buffer for non filled commit count */
	if (((commit_count - channel->subbuf_size) & channel->commit_count_mask)
	    - (BUFFER_TRUNC(cons_off, channel) >> channel->n_subbufs_order) != 0) {
		ERR("LTT : %s : subbuffer %lu has non filled "
			"commit count [cc, cc_sb] [%lu,%lu].\n",
			channel->channel_name, cons_idx, commit_count, commit_count_sb);
	}
	ERR("LTT : %s : commit count : %lu, subbuf size %zd\n",
			channel->channel_name, commit_count,
			channel->subbuf_size);
}

static void ltt_relay_print_errors(struct ust_trace *trace,
		struct ust_channel *channel, int cpu)
{
	struct ust_buffer *ltt_buf = channel->buf[cpu];
	long cons_off;

	/*
	 * Can be called in the error path of allocation when
	 * trans_channel_data is not yet set.
	 */
	if (!channel)
	        return;

//ust//	for (cons_off = 0; cons_off < rchan->alloc_size;
//ust//	     cons_off = SUBBUF_ALIGN(cons_off, rchan))
//ust//		ust_buffers_print_written(ltt_chan, cons_off, cpu);
	for (cons_off = uatomic_read(&ltt_buf->consumed);
			(SUBBUF_TRUNC(uatomic_read(&ltt_buf->offset),
				      channel)
			 - cons_off) > 0;
			cons_off = SUBBUF_ALIGN(cons_off, channel))
		ltt_relay_print_subbuffer_errors(channel, cons_off, cpu);
}

static void ltt_relay_print_buffer_errors(struct ust_channel *channel, int cpu)
{
	struct ust_trace *trace = channel->trace;
	struct ust_buffer *ltt_buf = channel->buf[cpu];

	if (uatomic_read(&ltt_buf->events_lost))
		ERR("channel %s: %ld events lost (cpu %d)",
			channel->channel_name,
			uatomic_read(&ltt_buf->events_lost), cpu);
	if (uatomic_read(&ltt_buf->corrupted_subbuffers))
		ERR("channel %s : %ld corrupted subbuffers (cpu %d)",
			channel->channel_name,
			uatomic_read(&ltt_buf->corrupted_subbuffers), cpu);

	ltt_relay_print_errors(trace, channel, cpu);
}

static void ltt_relay_release_channel(struct kref *kref)
{
	struct ust_channel *ltt_chan = _ust_container_of(kref,
			struct ust_channel, kref);
	free(ltt_chan->buf);
}

/*
 * Create ltt buffer.
 */
//ust// static int ltt_relay_create_buffer(struct ust_trace *trace,
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
//ust// 	uatomic_set(&ltt_buf->offset, ltt_subbuffer_header_size());
//ust// 	uatomic_set(&ltt_buf->consumed, 0);
//ust// 	uatomic_set(&ltt_buf->active_readers, 0);
//ust// 	for (j = 0; j < n_subbufs; j++)
//ust// 		uatomic_set(&ltt_buf->commit_count[j], 0);
//ust// 	init_waitqueue_head(&ltt_buf->write_wait);
//ust// 	uatomic_set(&ltt_buf->wakeup_readers, 0);
//ust// 	spin_lock_init(&ltt_buf->full_lock);
//ust//
//ust// 	ltt_buffer_begin_callback(buf, trace->start_tsc, 0);
//ust// 	/* atomic_add made on local variable on data that belongs to
//ust// 	 * various CPUs : ok because tracing not started (for this cpu). */
//ust// 	uatomic_add(&ltt_buf->commit_count[0], ltt_subbuffer_header_size());
//ust//
//ust// 	uatomic_set(&ltt_buf->events_lost, 0);
//ust// 	uatomic_set(&ltt_buf->corrupted_subbuffers, 0);
//ust//
//ust// 	return 0;
//ust// }

static int ust_buffers_init_buffer(struct ust_trace *trace,
		struct ust_channel *ltt_chan, struct ust_buffer *buf,
		unsigned int n_subbufs)
{
	unsigned int j;
	int fds[2];
	int result;

	buf->commit_count =
		zmalloc(sizeof(*buf->commit_count) * n_subbufs);
	if (!buf->commit_count)
		return -ENOMEM;
	kref_get(&trace->kref);
	kref_get(&trace->ltt_transport_kref);
	kref_get(&ltt_chan->kref);
	uatomic_set(&buf->offset, ltt_subbuffer_header_size());
	uatomic_set(&buf->consumed, 0);
	uatomic_set(&buf->active_readers, 0);
	for (j = 0; j < n_subbufs; j++) {
		uatomic_set(&buf->commit_count[j].cc, 0);
		uatomic_set(&buf->commit_count[j].cc_sb, 0);
	}
//ust//	init_waitqueue_head(&buf->write_wait);
//ust//	uatomic_set(&buf->wakeup_readers, 0);
//ust//	spin_lock_init(&buf->full_lock);

	ltt_buffer_begin(buf, trace->start_tsc, 0);

	uatomic_add(&buf->commit_count[0].cc, ltt_subbuffer_header_size());

	uatomic_set(&buf->events_lost, 0);
	uatomic_set(&buf->corrupted_subbuffers, 0);

	result = pipe(fds);
	if(result == -1) {
		PERROR("pipe");
		return -1;
	}
	buf->data_ready_fd_read = fds[0];
	buf->data_ready_fd_write = fds[1];

//ust//	buf->commit_seq = malloc(sizeof(buf->commit_seq) * n_subbufs);
//ust//	if(!ltt_buf->commit_seq) {
//ust//		return -1;
//ust//	}
	memset(buf->commit_seq, 0, sizeof(buf->commit_seq[0]) * n_subbufs);

	/* FIXME: decrementally destroy on error */

	return 0;
}

/* FIXME: use this function */
static void ust_buffers_destroy_buffer(struct ust_channel *ltt_chan, int cpu)
{
	struct ust_trace *trace = ltt_chan->trace;
	struct ust_buffer *ltt_buf = ltt_chan->buf[cpu];

	kref_put(&ltt_chan->trace->ltt_transport_kref,
		ltt_release_transport);
	ltt_relay_print_buffer_errors(ltt_chan, cpu);
//ust//	free(ltt_buf->commit_seq);
	free(ltt_buf->commit_count);
	ltt_buf->commit_count = NULL;
	kref_put(&ltt_chan->kref, ltt_relay_release_channel);
	kref_put(&trace->kref, ltt_release_trace);
//ust//	wake_up_interruptible(&trace->kref_wq);
}

static int ust_buffers_alloc_channel_buf_structs(struct ust_channel *chan)
{
	void *ptr;
	int result;
	size_t size;
	int i;

	size = PAGE_ALIGN(1);

	for(i=0; i<chan->n_cpus; i++) {

		result = chan->buf_struct_shmids[i] = shmget(getpid(), size, IPC_CREAT | IPC_EXCL | 0700);
		if(result == -1) {
			PERROR("shmget");
			goto destroy_previous;
		}

		/* FIXME: should have matching call to shmdt */
		ptr = shmat(chan->buf_struct_shmids[i], NULL, 0);
		if(ptr == (void *) -1) {
			perror("shmat");
			goto destroy_shm;
		}

		/* Already mark the shared memory for destruction. This will occur only
		 * when all users have detached.
		 */
		result = shmctl(chan->buf_struct_shmids[i], IPC_RMID, NULL);
		if(result == -1) {
			perror("shmctl");
			goto destroy_previous;
		}

		chan->buf[i] = ptr;
	}

	return 0;

	/* Jumping inside this loop occurs from within the other loop above with i as
	 * counter, so it unallocates the structures for the cpu = current_i down to
	 * zero. */
	for(; i>=0; i--) {
		destroy_shm:
		result = shmctl(chan->buf_struct_shmids[i], IPC_RMID, NULL);
		if(result == -1) {
			perror("shmctl");
		}

		destroy_previous:
		continue;
	}

	return -1;
}

/*
 * Create channel.
 */
static int ust_buffers_create_channel(const char *trace_name, struct ust_trace *trace,
	const char *channel_name, struct ust_channel *ltt_chan,
	unsigned int subbuf_size, unsigned int n_subbufs, int overwrite)
{
	int result;

	kref_init(&ltt_chan->kref);

	ltt_chan->trace = trace;
	ltt_chan->overwrite = overwrite;
	ltt_chan->n_subbufs_order = get_count_order(n_subbufs);
	ltt_chan->commit_count_mask = (~0UL >> ltt_chan->n_subbufs_order);
	ltt_chan->n_cpus = get_n_cpus();
//ust//	ltt_chan->buf = percpu_alloc_mask(sizeof(struct ltt_channel_buf_struct), GFP_KERNEL, cpu_possible_map);
	ltt_chan->buf = (void *) zmalloc(ltt_chan->n_cpus * sizeof(void *));
	if(ltt_chan->buf == NULL) {
		goto error;
	}
	ltt_chan->buf_struct_shmids = (int *) zmalloc(ltt_chan->n_cpus * sizeof(int));
	if(ltt_chan->buf_struct_shmids == NULL)
		goto free_buf;

	result = ust_buffers_alloc_channel_buf_structs(ltt_chan);
	if(result != 0) {
		goto free_buf_struct_shmids;
	}

	result = ust_buffers_channel_open(ltt_chan, subbuf_size, n_subbufs);
	if (result != 0) {
		ERR("Cannot open channel for trace %s", trace_name);
		goto unalloc_buf_structs;
	}

	return 0;

unalloc_buf_structs:
	/* FIXME: put a call here to unalloc the buf structs! */

free_buf_struct_shmids:
	free(ltt_chan->buf_struct_shmids);

free_buf:
	free(ltt_chan->buf);

error:
	return -1;
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
//ust//		if (uatomic_read(&ltt_buf->wakeup_readers) == 1) {
//ust//			uatomic_set(&ltt_buf->wakeup_readers, 0);
//ust//			wake_up_interruptible(&rchan->buf[i]->read_wait);
//ust//		}
//ust//	}
}

static void ltt_relay_finish_buffer(struct ust_channel *channel, unsigned int cpu)
{
//	int result;

	if (channel->buf[cpu]) {
		struct ust_buffer *buf = channel->buf[cpu];
		ltt_force_switch(buf, FORCE_FLUSH);
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
	unsigned int i;

	for(i=0; i<channel->n_cpus; i++) {
		ltt_relay_finish_buffer(channel, i);
	}
}

static void ltt_relay_remove_channel(struct ust_channel *channel)
{
	ust_buffers_channel_close(channel);
	kref_put(&channel->kref, ltt_relay_release_channel);
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
static void ltt_reserve_switch_old_subbuf(
		struct ust_channel *chan, struct ust_buffer *buf,
		struct ltt_reserve_switch_offsets *offsets, u64 *tsc)
{
	long oldidx = SUBBUF_INDEX(offsets->old - 1, chan);
	long commit_count, padding_size;

	padding_size = chan->subbuf_size
			- (SUBBUF_OFFSET(offsets->old - 1, chan) + 1);
	ltt_buffer_end(buf, *tsc, offsets->old, oldidx);

	/*
	 * Must write slot data before incrementing commit count.
	 * This compiler cmm_barrier is upgraded into a cmm_smp_wmb() by the IPI
	 * sent by get_subbuf() when it does its cmm_smp_rmb().
	 */
	cmm_smp_wmb();
	uatomic_add(&buf->commit_count[oldidx].cc, padding_size);
	commit_count = uatomic_read(&buf->commit_count[oldidx].cc);
	ltt_check_deliver(chan, buf, offsets->old - 1, commit_count, oldidx);
	ltt_write_commit_counter(chan, buf, oldidx,
		offsets->old, commit_count, padding_size);
}

/*
 * ltt_reserve_switch_new_subbuf: Populate new subbuffer.
 *
 * This code can be executed unordered : writers may already have written to the
 * sub-buffer before this code gets executed, caution.  The commit makes sure
 * that this code is executed before the deliver of this sub-buffer.
 */
static void ltt_reserve_switch_new_subbuf(
		struct ust_channel *chan, struct ust_buffer *buf,
		struct ltt_reserve_switch_offsets *offsets, u64 *tsc)
{
	long beginidx = SUBBUF_INDEX(offsets->begin, chan);
	long commit_count;

	ltt_buffer_begin(buf, *tsc, beginidx);

	/*
	 * Must write slot data before incrementing commit count.
	 * This compiler cmm_barrier is upgraded into a cmm_smp_wmb() by the IPI
	 * sent by get_subbuf() when it does its cmm_smp_rmb().
	 */
	cmm_smp_wmb();
	uatomic_add(&buf->commit_count[beginidx].cc, ltt_subbuffer_header_size());
	commit_count = uatomic_read(&buf->commit_count[beginidx].cc);
	/* Check if the written buffer has to be delivered */
	ltt_check_deliver(chan, buf, offsets->begin, commit_count, beginidx);
	ltt_write_commit_counter(chan, buf, beginidx,
		offsets->begin, commit_count, ltt_subbuffer_header_size());
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
static void ltt_reserve_end_switch_current(
		struct ust_channel *chan,
		struct ust_buffer *buf,
		struct ltt_reserve_switch_offsets *offsets, u64 *tsc)
{
	long endidx = SUBBUF_INDEX(offsets->end - 1, chan);
	long commit_count, padding_size;

	padding_size = chan->subbuf_size
			- (SUBBUF_OFFSET(offsets->end - 1, chan) + 1);

	ltt_buffer_end(buf, *tsc, offsets->end, endidx);

	/*
	 * Must write slot data before incrementing commit count.
	 * This compiler cmm_barrier is upgraded into a cmm_smp_wmb() by the IPI
	 * sent by get_subbuf() when it does its cmm_smp_rmb().
	 */
	cmm_smp_wmb();
	uatomic_add(&buf->commit_count[endidx].cc, padding_size);
	commit_count = uatomic_read(&buf->commit_count[endidx].cc);
	ltt_check_deliver(chan, buf,
		offsets->end - 1, commit_count, endidx);
	ltt_write_commit_counter(chan, buf, endidx,
		offsets->end, commit_count, padding_size);
}

/*
 * Returns :
 * 0 if ok
 * !0 if execution must be aborted.
 */
static int ltt_relay_try_switch_slow(
		enum force_switch_mode mode,
		struct ust_channel *chan,
		struct ust_buffer *buf,
		struct ltt_reserve_switch_offsets *offsets,
		u64 *tsc)
{
	long subbuf_index;
	long reserve_commit_diff;

	offsets->begin = uatomic_read(&buf->offset);
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
	reserve_commit_diff =
		(BUFFER_TRUNC(offsets->begin, buf->chan)
		 >> chan->n_subbufs_order)
		- (uatomic_read(&buf->commit_count[subbuf_index].cc_sb)
			& chan->commit_count_mask);
	if (reserve_commit_diff == 0) {
		/* Next buffer not corrupted. */
		if (mode == FORCE_ACTIVE
		    && !chan->overwrite
		    && offsets->begin - uatomic_read(&buf->consumed)
		       >= chan->alloc_size) {
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

/*
 * Force a sub-buffer switch for a per-cpu buffer. This operation is
 * completely reentrant : can be called while tracing is active with
 * absolutely no lock held.
 */
void ltt_force_switch_lockless_slow(struct ust_buffer *buf,
		enum force_switch_mode mode)
{
	struct ust_channel *chan = buf->chan;
	struct ltt_reserve_switch_offsets offsets;
	u64 tsc;

	offsets.size = 0;

	DBG("Switching (forced) %s_%d", chan->channel_name, buf->cpu);
	/*
	 * Perform retryable operations.
	 */
	do {
		if (ltt_relay_try_switch_slow(mode, chan, buf,
				&offsets, &tsc))
			return;
	} while (uatomic_cmpxchg(&buf->offset, offsets.old,
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
	if (mode == FORCE_ACTIVE) {
		ltt_reserve_push_reader(chan, buf, offsets.end - 1);
//ust//		ltt_clear_noref_flag(chan, buf, SUBBUF_INDEX(offsets.end - 1, chan));
	}

	/*
	 * Switch old subbuffer if needed.
	 */
	if (offsets.end_switch_old) {
//ust//		ltt_clear_noref_flag(rchan, buf, SUBBUF_INDEX(offsets.old - 1, rchan));
		ltt_reserve_switch_old_subbuf(chan, buf, &offsets, &tsc);
	}

	/*
	 * Populate new subbuffer.
	 */
	if (mode == FORCE_ACTIVE)
		ltt_reserve_switch_new_subbuf(chan, buf, &offsets, &tsc);
}

/*
 * Returns :
 * 0 if ok
 * !0 if execution must be aborted.
 */
static int ltt_relay_try_reserve_slow(struct ust_channel *chan, struct ust_buffer *buf,
		struct ltt_reserve_switch_offsets *offsets, size_t data_size,
		u64 *tsc, unsigned int *rflags, int largest_align)
{
	long reserve_commit_diff;

	offsets->begin = uatomic_read(&buf->offset);
	offsets->old = offsets->begin;
	offsets->begin_switch = 0;
	offsets->end_switch_current = 0;
	offsets->end_switch_old = 0;

	*tsc = trace_clock_read64();
	if (last_tsc_overflow(buf, *tsc))
		*rflags = LTT_RFLAG_ID_SIZE_TSC;

	if (unlikely(SUBBUF_OFFSET(offsets->begin, buf->chan) == 0)) {
		offsets->begin_switch = 1;		/* For offsets->begin */
	} else {
		offsets->size = ust_get_header_size(chan,
					offsets->begin, data_size,
					&offsets->before_hdr_pad, *rflags);
		offsets->size += ltt_align(offsets->begin + offsets->size,
					   largest_align)
				 + data_size;
		if (unlikely((SUBBUF_OFFSET(offsets->begin, buf->chan) +
			     offsets->size) > buf->chan->subbuf_size)) {
			offsets->end_switch_old = 1;	/* For offsets->old */
			offsets->begin_switch = 1;	/* For offsets->begin */
		}
	}
	if (unlikely(offsets->begin_switch)) {
		long subbuf_index;

		/*
		 * We are typically not filling the previous buffer completely.
		 */
		if (likely(offsets->end_switch_old))
			offsets->begin = SUBBUF_ALIGN(offsets->begin,
						      buf->chan);
		offsets->begin = offsets->begin + ltt_subbuffer_header_size();
		/* Test new buffer integrity */
		subbuf_index = SUBBUF_INDEX(offsets->begin, buf->chan);
		reserve_commit_diff =
		  (BUFFER_TRUNC(offsets->begin, buf->chan)
		   >> chan->n_subbufs_order)
		  - (uatomic_read(&buf->commit_count[subbuf_index].cc_sb)
				& chan->commit_count_mask);
		if (likely(reserve_commit_diff == 0)) {
			/* Next buffer not corrupted. */
			if (unlikely(!chan->overwrite &&
				(SUBBUF_TRUNC(offsets->begin, buf->chan)
				 - SUBBUF_TRUNC(uatomic_read(
							&buf->consumed),
						buf->chan))
				>= chan->alloc_size)) {
				/*
				 * We do not overwrite non consumed buffers
				 * and we are full : event is lost.
				 */
				uatomic_inc(&buf->events_lost);
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
			 * Next subbuffer corrupted. Drop event in normal and
			 * overwrite mode. Caused by either a writer OOPS or
			 * too many nested writes over a reserve/commit pair.
			 */
			uatomic_inc(&buf->events_lost);
			return -1;
		}
		offsets->size = ust_get_header_size(chan,
					offsets->begin, data_size,
					&offsets->before_hdr_pad, *rflags);
		offsets->size += ltt_align(offsets->begin + offsets->size,
					   largest_align)
				 + data_size;
		if (unlikely((SUBBUF_OFFSET(offsets->begin, buf->chan)
			     + offsets->size) > buf->chan->subbuf_size)) {
			/*
			 * Event too big for subbuffers, report error, don't
			 * complete the sub-buffer switch.
			 */
			uatomic_inc(&buf->events_lost);
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

	if (unlikely((SUBBUF_OFFSET(offsets->end, buf->chan)) == 0)) {
		/*
		 * The offset_end will fall at the very beginning of the next
		 * subbuffer.
		 */
		offsets->end_switch_current = 1;	/* For offsets->begin */
	}
	return 0;
}

/**
 * ltt_relay_reserve_slot_lockless_slow - Atomic slot reservation in a buffer.
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
int ltt_reserve_slot_lockless_slow(struct ust_channel *chan,
		struct ust_trace *trace, size_t data_size,
		int largest_align, int cpu,
		struct ust_buffer **ret_buf,
		size_t *slot_size, long *buf_offset,
		u64 *tsc, unsigned int *rflags)
{
	struct ust_buffer *buf = *ret_buf = chan->buf[cpu];
	struct ltt_reserve_switch_offsets offsets;

	offsets.size = 0;

	do {
		if (unlikely(ltt_relay_try_reserve_slow(chan, buf, &offsets,
				data_size, tsc, rflags, largest_align)))
			return -ENOSPC;
	} while (unlikely(uatomic_cmpxchg(&buf->offset, offsets.old,
			offsets.end) != offsets.old));

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
	ltt_reserve_push_reader(chan, buf, offsets.end - 1);

	/*
	 * Clear noref flag for this subbuffer.
	 */
//ust//	ltt_clear_noref_flag(chan, buf, SUBBUF_INDEX(offsets.end - 1, chan));

	/*
	 * Switch old subbuffer if needed.
	 */
	if (unlikely(offsets.end_switch_old)) {
//ust//		ltt_clear_noref_flag(chan, buf, SUBBUF_INDEX(offsets.old - 1, chan));
		ltt_reserve_switch_old_subbuf(chan, buf, &offsets, tsc);
		DBG("Switching %s_%d", chan->channel_name, cpu);
	}

	/*
	 * Populate new subbuffer.
	 */
	if (unlikely(offsets.begin_switch))
		ltt_reserve_switch_new_subbuf(chan, buf, &offsets, tsc);

	if (unlikely(offsets.end_switch_current))
		ltt_reserve_end_switch_current(chan, buf, &offsets, tsc);

	*slot_size = offsets.size;
	*buf_offset = offsets.begin + offsets.before_hdr_pad;
	return 0;
}

static struct ltt_transport ust_relay_transport = {
	.name = "ustrelay",
	.ops = {
		.create_channel = ust_buffers_create_channel,
		.finish_channel = ltt_relay_finish_channel,
		.remove_channel = ltt_relay_remove_channel,
		.wakeup_channel = ltt_relay_async_wakeup_chan,
	},
};

static char initialized = 0;

void __attribute__((constructor)) init_ustrelay_transport(void)
{
	if(!initialized) {
		ltt_transport_register(&ust_relay_transport);
		initialized = 1;
	}
}

static void __attribute__((destructor)) ust_buffers_exit(void)
{
	ltt_transport_unregister(&ust_relay_transport);
}

size_t ltt_write_event_header_slow(struct ust_channel *channel,
		struct ust_buffer *buf, long buf_offset,
		u16 eID, u32 event_size,
		u64 tsc, unsigned int rflags)
{
	struct ltt_event_header header;
	u16 small_size;

	switch (rflags) {
	case LTT_RFLAG_ID_SIZE_TSC:
		header.id_time = 29 << LTT_TSC_BITS;
		break;
	case LTT_RFLAG_ID_SIZE:
		header.id_time = 30 << LTT_TSC_BITS;
		break;
	case LTT_RFLAG_ID:
		header.id_time = 31 << LTT_TSC_BITS;
		break;
	}

	header.id_time |= (u32)tsc & LTT_TSC_MASK;
	ust_buffers_write(buf, buf_offset, &header, sizeof(header));
	buf_offset += sizeof(header);

	switch (rflags) {
	case LTT_RFLAG_ID_SIZE_TSC:
		small_size = (u16)min_t(u32, event_size, LTT_MAX_SMALL_SIZE);
		ust_buffers_write(buf, buf_offset,
			&eID, sizeof(u16));
		buf_offset += sizeof(u16);
		ust_buffers_write(buf, buf_offset,
			&small_size, sizeof(u16));
		buf_offset += sizeof(u16);
		if (small_size == LTT_MAX_SMALL_SIZE) {
			ust_buffers_write(buf, buf_offset,
				&event_size, sizeof(u32));
			buf_offset += sizeof(u32);
		}
		buf_offset += ltt_align(buf_offset, sizeof(u64));
		ust_buffers_write(buf, buf_offset,
			&tsc, sizeof(u64));
		buf_offset += sizeof(u64);
		break;
	case LTT_RFLAG_ID_SIZE:
		small_size = (u16)min_t(u32, event_size, LTT_MAX_SMALL_SIZE);
		ust_buffers_write(buf, buf_offset,
			&eID, sizeof(u16));
		buf_offset += sizeof(u16);
		ust_buffers_write(buf, buf_offset,
			&small_size, sizeof(u16));
		buf_offset += sizeof(u16);
		if (small_size == LTT_MAX_SMALL_SIZE) {
			ust_buffers_write(buf, buf_offset,
				&event_size, sizeof(u32));
			buf_offset += sizeof(u32);
		}
		break;
	case LTT_RFLAG_ID:
		ust_buffers_write(buf, buf_offset,
			&eID, sizeof(u16));
		buf_offset += sizeof(u16);
		break;
	}

	return buf_offset;
}
