/*
 * buffers.c
 * LTTng userspace tracer buffering system
 *
 * Copyright (C) 2009 - Pierre-Marc Fournier (pierre-marc dot fournier at polymtl dot ca)
 * Copyright (C) 2008-2011 - Mathieu Desnoyers (mathieu.desnoyers@polymtl.ca)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; version 2.1 of
 * the License.
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

/*
 * Note: this code does not support the ref/noref flag and reader-owned
 * subbuffer scheme. Therefore, flight recorder mode uses a mechanism
 * where the reader can read corrupted data (and detect this), thus
 * returning -EIO.
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
#include "usterr_signal_safe.h"

struct ltt_reserve_switch_offsets {
	long begin, end, old;
	long begin_switch, end_switch_current, end_switch_old;
	size_t before_hdr_pad, size;
};


static DEFINE_MUTEX(ust_buffers_channels_mutex);
static CDS_LIST_HEAD(ust_buffers_channels);

static void ltt_force_switch(struct ust_buffer *buf,
		enum force_switch_mode mode);

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
	/*
	 * No memory barrier needed to order data_data/sb_size vs commit count
	 * update, because commit count update contains a compiler barrier that
	 * ensures the order of the writes are OK from a program POV. It only
	 * matters for crash dump recovery which is not executed concurrently,
	 * so memory write order does not matter.
	 */
	ltt_write_trace_header(channel->trace, header);
}

static int map_buf_data(struct ust_buffer *buf, size_t *size)
{
	void *ptr;
	int result;

	*size = PAGE_ALIGN(*size);

	result = buf->shmid = shmget(getpid(), *size, IPC_CREAT | IPC_EXCL | 0700);
	if (result < 0 && errno == EINVAL) {
		ERR("shmget() returned EINVAL; maybe /proc/sys/kernel/shmmax should be increased.");
		return -1;
	} else if (result < 0) {
		PERROR("shmget");
		return -1;
	}

	ptr = shmat(buf->shmid, NULL, 0);
	if (ptr == (void *) -1) {
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

static int open_buf(struct ust_channel *chan, int cpu)
{
	int result, fds[2];
	unsigned int j;
	struct ust_trace *trace = chan->trace;
	struct ust_buffer *buf = chan->buf[cpu];
	unsigned int n_subbufs = chan->subbuf_cnt;


	result = map_buf_data(buf, &chan->alloc_size);
	if (result < 0)
		return -1;

	buf->commit_count =
		zmalloc(sizeof(*buf->commit_count) * n_subbufs);
	if (!buf->commit_count)
		goto unmap_buf;

	result = pipe(fds);
	if (result < 0) {
		PERROR("pipe");
		goto free_commit_count;
	}
	buf->data_ready_fd_read = fds[0];
	buf->data_ready_fd_write = fds[1];

	buf->cpu = cpu;
	buf->chan = chan;

	uatomic_set(&buf->offset, ltt_subbuffer_header_size());
	uatomic_set(&buf->consumed, 0);
	uatomic_set(&buf->active_readers, 0);
	for (j = 0; j < n_subbufs; j++) {
		uatomic_set(&buf->commit_count[j].cc, 0);
		uatomic_set(&buf->commit_count[j].cc_sb, 0);
	}

	ltt_buffer_begin(buf, trace->start_tsc, 0);

	uatomic_add(&buf->commit_count[0].cc, ltt_subbuffer_header_size());

	uatomic_set(&buf->events_lost, 0);
	uatomic_set(&buf->corrupted_subbuffers, 0);

	memset(buf->commit_seq, 0, sizeof(buf->commit_seq[0]) * n_subbufs);

	return 0;

free_commit_count:
	free(buf->commit_count);

unmap_buf:
	if (shmdt(buf->buf_data) < 0) {
		PERROR("shmdt failed");
	}

	return -1;
}

static void close_buf(struct ust_buffer *buf)
{
	int result;

	result = shmdt(buf->buf_data);
	if (result < 0) {
		PERROR("shmdt");
	}

	result = close(buf->data_ready_fd_read);
	if (result < 0) {
		PERROR("close");
	}

	result = close(buf->data_ready_fd_write);
	if (result < 0 && errno != EBADF) {
		PERROR("close");
	}
}


static int open_channel(struct ust_channel *chan, size_t subbuf_size,
			size_t subbuf_cnt)
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

	pthread_mutex_lock(&ust_buffers_channels_mutex);
	for (i=0; i < chan->n_cpus; i++) {
		result = open_buf(chan, i);
		if (result == -1)
			goto error;
	}
	cds_list_add(&chan->list, &ust_buffers_channels);
	pthread_mutex_unlock(&ust_buffers_channels_mutex);

	return 0;

	/* Error handling */
error:
	for(i--; i >= 0; i--)
		close_buf(chan->buf[i]);

	pthread_mutex_unlock(&ust_buffers_channels_mutex);
	return -1;
}

static void close_channel(struct ust_channel *chan)
{
	int i;
	if(!chan)
		return;

	pthread_mutex_lock(&ust_buffers_channels_mutex);
	/*
	 * checking for chan->buf[i] being NULL or not is useless in
	 * practice because we allocate buffers for all possible cpus.
	 * However, should we decide to change this and only allocate
	 * for online cpus, this check becomes useful.
	 */
	for (i=0; i<chan->n_cpus; i++) {
		if (chan->buf[i])
			close_buf(chan->buf[i]);
	}

	cds_list_del(&chan->list);

	pthread_mutex_unlock(&ust_buffers_channels_mutex);
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

	header->sb_size = PAGE_ALIGN(data_size);
	header->cycle_count_end = tsc;
	header->events_lost = uatomic_read(&buf->events_lost);
	header->subbuf_corrupt = uatomic_read(&buf->corrupted_subbuffers);
	if(unlikely(header->events_lost > 0)) {
		DBG("Some events (%d) were lost in %s_%d", header->events_lost, buf->chan->channel_name, buf->cpu);
	}
	/*
	 * Makes sure data_size write happens after write of the rest of the
	 * buffer end data, because data_size is used to identify a completely
	 * written subbuffer in a crash dump.
	 */
	cmm_barrier();
	header->data_size = data_size;
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
	 */

	/*
	 * Local rmb to match the remote wmb to read the commit count before the
	 * buffer data and the write offset.
	 */
	cmm_smp_rmb();

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

	if (uatomic_cmpxchg(&buf->consumed, consumed_old,
				consumed_new)
	    != consumed_old) {
		/* We have been pushed by the writer : the last
		 * buffer read _is_ corrupted! It can also
		 * happen if this is a buffer we never got. */
		return -EIO;
	} else {
		/* tell the client that buffer is now unfull */
		int index;
		long data;
		index = SUBBUF_INDEX(consumed_old, buf->chan);
		data = BUFFER_OFFSET(consumed_old, buf->chan);
		ltt_buf_unfull(buf, index, data);
	}
	return 0;
}

static int map_buf_structs(struct ust_channel *chan)
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

static int unmap_buf_structs(struct ust_channel *chan)
{
	int i;

	for (i=0; i < chan->n_cpus; i++) {
		if (shmdt(chan->buf[i]) < 0) {
			PERROR("shmdt");
		}
	}
	return 0;
}

/*
 * Create channel.
 */
static int create_channel(const char *trace_name, struct ust_trace *trace,
	const char *channel_name, struct ust_channel *chan,
	unsigned int subbuf_size, unsigned int n_subbufs, int overwrite)
{
	int i, result;

	chan->trace = trace;
	chan->overwrite = overwrite;
	chan->n_subbufs_order = get_count_order(n_subbufs);
	chan->commit_count_mask = (~0UL >> chan->n_subbufs_order);
	chan->n_cpus = get_n_cpus();

	/* These mappings should ideall be per-cpu, if somebody can do that
	 * from userspace, that would be cool!
	 */
	chan->buf = (void *) zmalloc(chan->n_cpus * sizeof(void *));
	if(chan->buf == NULL) {
		goto error;
	}
	chan->buf_struct_shmids = (int *) zmalloc(chan->n_cpus * sizeof(int));
	if(chan->buf_struct_shmids == NULL)
		goto free_buf;

	result = map_buf_structs(chan);
	if(result != 0) {
		goto free_buf_struct_shmids;
	}

	result = open_channel(chan, subbuf_size, n_subbufs);
	if (result != 0) {
		ERR("Cannot open channel for trace %s", trace_name);
		goto unmap_buf_structs;
	}

	return 0;

unmap_buf_structs:
	for (i=0; i < chan->n_cpus; i++) {
		if (shmdt(chan->buf[i]) < 0) {
			PERROR("shmdt bufstruct");
		}
	}

free_buf_struct_shmids:
	free(chan->buf_struct_shmids);

free_buf:
	free(chan->buf);

error:
	return -1;
}


static void remove_channel(struct ust_channel *chan)
{
	close_channel(chan);

	unmap_buf_structs(chan);

	free(chan->buf_struct_shmids);

	free(chan->buf);
}

static void ltt_relay_async_wakeup_chan(struct ust_channel *ltt_channel)
{
}

static void ltt_relay_finish_buffer(struct ust_channel *channel, unsigned int cpu)
{
	if (channel->buf[cpu]) {
		struct ust_buffer *buf = channel->buf[cpu];
		ltt_force_switch(buf, FORCE_FLUSH);

		/* closing the pipe tells the consumer the buffer is finished */
		close(buf->data_ready_fd_write);
	}
}


static void finish_channel(struct ust_channel *channel)
{
	unsigned int i;

	for (i=0; i<channel->n_cpus; i++) {
		ltt_relay_finish_buffer(channel, i);
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
	 * This compiler barrier is upgraded into a cmm_smp_wmb() by the IPI
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
	 * This compiler barrier is upgraded into a cmm_smp_wmb() by the IPI
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
	 * This compiler barrier is upgraded into a cmm_smp_wmb() by the IPI
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
	}

	/*
	 * Switch old subbuffer if needed.
	 */
	if (offsets.end_switch_old) {
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
	 * Switch old subbuffer if needed.
	 */
	if (unlikely(offsets.end_switch_old)) {
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
		.create_channel = create_channel,
		.finish_channel = finish_channel,
		.remove_channel = remove_channel,
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
	default:
		WARN_ON_ONCE(1);
		header.id_time = 0;
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
