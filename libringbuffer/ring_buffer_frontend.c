/*
 * ring_buffer_frontend.c
 *
 * Copyright (C) 2005-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; only
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 *
 * Ring buffer wait-free buffer synchronization. Producer-consumer and flight
 * recorder (overwrite) modes. See thesis:
 *
 * Desnoyers, Mathieu (2009), "Low-Impact Operating System Tracing", Ph.D.
 * dissertation, Ecole Polytechnique de Montreal.
 * http://www.lttng.org/pub/thesis/desnoyers-dissertation-2009-12.pdf
 *
 * - Algorithm presentation in Chapter 5:
 *     "Lockless Multi-Core High-Throughput Buffering".
 * - Algorithm formal verification in Section 8.6:
 *     "Formal verification of LTTng"
 *
 * Author:
 *	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Inspired from LTT and RelayFS:
 *  Karim Yaghmour <karim@opersys.com>
 *  Tom Zanussi <zanussi@us.ibm.com>
 *  Bob Wisniewski <bob@watson.ibm.com>
 * And from K42 :
 *  Bob Wisniewski <bob@watson.ibm.com>
 *
 * Buffer reader semantic :
 *
 * - get_subbuf_size
 * while buffer is not finalized and empty
 *   - get_subbuf
 *     - if return value != 0, continue
 *   - splice one subbuffer worth of data to a pipe
 *   - splice the data from pipe to disk/network
 *   - put_subbuf
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <urcu/compiler.h>
#include <urcu/ref.h>
#include <urcu/tls-compat.h>
#include <helper.h>

#include "smp.h"
#include <lttng/ringbuffer-config.h>
#include "vatomic.h"
#include "backend.h"
#include "frontend.h"
#include "shm.h"
#include "tlsfixup.h"
#include "../liblttng-ust/compat.h"	/* For ENODATA */

#ifndef max
#define max(a, b)	((a) > (b) ? (a) : (b))
#endif

/* Print DBG() messages about events lost only every 1048576 hits */
#define DBG_PRINT_NR_LOST	(1UL << 20)

#define LTTNG_UST_RB_SIG_FLUSH		SIGRTMIN
#define LTTNG_UST_RB_SIG_READ		SIGRTMIN + 1
#define LTTNG_UST_RB_SIG_TEARDOWN	SIGRTMIN + 2
#define CLOCKID		CLOCK_MONOTONIC

/*
 * Use POSIX SHM: shm_open(3) and shm_unlink(3).
 * close(2) to close the fd returned by shm_open.
 * shm_unlink releases the shared memory object name.
 * ftruncate(2) sets the size of the memory object.
 * mmap/munmap maps the shared memory obj to a virtual address in the
 * calling proceess (should be done both in libust and consumer).
 * See shm_overview(7) for details.
 * Pass file descriptor returned by shm_open(3) to ltt-sessiond through
 * a UNIX socket.
 *
 * Since we don't need to access the object using its name, we can
 * immediately shm_unlink(3) it, and only keep the handle with its file
 * descriptor.
 */

/*
 * Internal structure representing offsets to use at a sub-buffer switch.
 */
struct switch_offsets {
	unsigned long begin, end, old;
	size_t pre_header_padding, size;
	unsigned int switch_new_start:1, switch_new_end:1, switch_old_start:1,
		     switch_old_end:1;
};

DEFINE_URCU_TLS(unsigned int, lib_ring_buffer_nesting);

/*
 * wakeup_fd_mutex protects wakeup fd use by timer from concurrent
 * close.
 */
static pthread_mutex_t wakeup_fd_mutex = PTHREAD_MUTEX_INITIALIZER;

static
void lib_ring_buffer_print_errors(struct channel *chan,
				struct lttng_ust_lib_ring_buffer *buf, int cpu,
				struct lttng_ust_shm_handle *handle);

/*
 * Handle timer teardown race wrt memory free of private data by
 * ring buffer signals are handled by a single thread, which permits
 * a synchronization point between handling of each signal.
 * Protected by the lock within the structure.
 */
struct timer_signal_data {
	pthread_t tid;	/* thread id managing signals */
	int setup_done;
	int qs_done;
	pthread_mutex_t lock;
};

static struct timer_signal_data timer_signal = {
	.tid = 0,
	.setup_done = 0,
	.qs_done = 0,
	.lock = PTHREAD_MUTEX_INITIALIZER,
};

/**
 * lib_ring_buffer_reset - Reset ring buffer to initial values.
 * @buf: Ring buffer.
 *
 * Effectively empty the ring buffer. Should be called when the buffer is not
 * used for writing. The ring buffer can be opened for reading, but the reader
 * should not be using the iterator concurrently with reset. The previous
 * current iterator record is reset.
 */
void lib_ring_buffer_reset(struct lttng_ust_lib_ring_buffer *buf,
			   struct lttng_ust_shm_handle *handle)
{
	struct channel *chan = shmp(handle, buf->backend.chan);
	const struct lttng_ust_lib_ring_buffer_config *config = &chan->backend.config;
	unsigned int i;

	/*
	 * Reset iterator first. It will put the subbuffer if it currently holds
	 * it.
	 */
	v_set(config, &buf->offset, 0);
	for (i = 0; i < chan->backend.num_subbuf; i++) {
		v_set(config, &shmp_index(handle, buf->commit_hot, i)->cc, 0);
		v_set(config, &shmp_index(handle, buf->commit_hot, i)->seq, 0);
		v_set(config, &shmp_index(handle, buf->commit_cold, i)->cc_sb, 0);
	}
	uatomic_set(&buf->consumed, 0);
	uatomic_set(&buf->record_disabled, 0);
	v_set(config, &buf->last_tsc, 0);
	lib_ring_buffer_backend_reset(&buf->backend, handle);
	/* Don't reset number of active readers */
	v_set(config, &buf->records_lost_full, 0);
	v_set(config, &buf->records_lost_wrap, 0);
	v_set(config, &buf->records_lost_big, 0);
	v_set(config, &buf->records_count, 0);
	v_set(config, &buf->records_overrun, 0);
	buf->finalized = 0;
}

/**
 * channel_reset - Reset channel to initial values.
 * @chan: Channel.
 *
 * Effectively empty the channel. Should be called when the channel is not used
 * for writing. The channel can be opened for reading, but the reader should not
 * be using the iterator concurrently with reset. The previous current iterator
 * record is reset.
 */
void channel_reset(struct channel *chan)
{
	/*
	 * Reset iterators first. Will put the subbuffer if held for reading.
	 */
	uatomic_set(&chan->record_disabled, 0);
	/* Don't reset commit_count_mask, still valid */
	channel_backend_reset(&chan->backend);
	/* Don't reset switch/read timer interval */
	/* Don't reset notifiers and notifier enable bits */
	/* Don't reset reader reference count */
}

/*
 * Must be called under cpu hotplug protection.
 */
int lib_ring_buffer_create(struct lttng_ust_lib_ring_buffer *buf,
			   struct channel_backend *chanb, int cpu,
			   struct lttng_ust_shm_handle *handle,
			   struct shm_object *shmobj)
{
	const struct lttng_ust_lib_ring_buffer_config *config = &chanb->config;
	struct channel *chan = caa_container_of(chanb, struct channel, backend);
	void *priv = channel_get_private(chan);
	size_t subbuf_header_size;
	uint64_t tsc;
	int ret;

	/* Test for cpu hotplug */
	if (buf->backend.allocated)
		return 0;

	ret = lib_ring_buffer_backend_create(&buf->backend, &chan->backend,
			cpu, handle, shmobj);
	if (ret)
		return ret;

	align_shm(shmobj, __alignof__(struct commit_counters_hot));
	set_shmp(buf->commit_hot,
		 zalloc_shm(shmobj,
			sizeof(struct commit_counters_hot) * chan->backend.num_subbuf));
	if (!shmp(handle, buf->commit_hot)) {
		ret = -ENOMEM;
		goto free_chanbuf;
	}

	align_shm(shmobj, __alignof__(struct commit_counters_cold));
	set_shmp(buf->commit_cold,
		 zalloc_shm(shmobj,
			sizeof(struct commit_counters_cold) * chan->backend.num_subbuf));
	if (!shmp(handle, buf->commit_cold)) {
		ret = -ENOMEM;
		goto free_commit;
	}

	/*
	 * Write the subbuffer header for first subbuffer so we know the total
	 * duration of data gathering.
	 */
	subbuf_header_size = config->cb.subbuffer_header_size();
	v_set(config, &buf->offset, subbuf_header_size);
	subbuffer_id_clear_noref(config, &shmp_index(handle, buf->backend.buf_wsb, 0)->id);
	tsc = config->cb.ring_buffer_clock_read(shmp(handle, buf->backend.chan));
	config->cb.buffer_begin(buf, tsc, 0, handle);
	v_add(config, subbuf_header_size, &shmp_index(handle, buf->commit_hot, 0)->cc);

	if (config->cb.buffer_create) {
		ret = config->cb.buffer_create(buf, priv, cpu, chanb->name, handle);
		if (ret)
			goto free_init;
	}
	buf->backend.allocated = 1;
	return 0;

	/* Error handling */
free_init:
	/* commit_cold will be freed by shm teardown */
free_commit:
	/* commit_hot will be freed by shm teardown */
free_chanbuf:
	return ret;
}

static
void lib_ring_buffer_channel_switch_timer(int sig, siginfo_t *si, void *uc)
{
	const struct lttng_ust_lib_ring_buffer_config *config;
	struct lttng_ust_shm_handle *handle;
	struct channel *chan;
	int cpu;

	assert(CMM_LOAD_SHARED(timer_signal.tid) == pthread_self());

	chan = si->si_value.sival_ptr;
	handle = chan->handle;
	config = &chan->backend.config;

	DBG("Switch timer for channel %p\n", chan);

	/*
	 * Only flush buffers periodically if readers are active.
	 */
	pthread_mutex_lock(&wakeup_fd_mutex);
	if (config->alloc == RING_BUFFER_ALLOC_PER_CPU) {
		for_each_possible_cpu(cpu) {
			struct lttng_ust_lib_ring_buffer *buf =
				shmp(handle, chan->backend.buf[cpu].shmp);
			if (uatomic_read(&buf->active_readers))
				lib_ring_buffer_switch_slow(buf, SWITCH_ACTIVE,
					chan->handle);
		}
	} else {
		struct lttng_ust_lib_ring_buffer *buf =
			shmp(handle, chan->backend.buf[0].shmp);

		if (uatomic_read(&buf->active_readers))
			lib_ring_buffer_switch_slow(buf, SWITCH_ACTIVE,
				chan->handle);
	}
	pthread_mutex_unlock(&wakeup_fd_mutex);
	return;
}

static
void lib_ring_buffer_channel_do_read(struct channel *chan)
{
	const struct lttng_ust_lib_ring_buffer_config *config;
	struct lttng_ust_shm_handle *handle;
	int cpu;

	handle = chan->handle;
	config = &chan->backend.config;

	/*
	 * Only flush buffers periodically if readers are active.
	 */
	pthread_mutex_lock(&wakeup_fd_mutex);
	if (config->alloc == RING_BUFFER_ALLOC_PER_CPU) {
		for_each_possible_cpu(cpu) {
			struct lttng_ust_lib_ring_buffer *buf =
				shmp(handle, chan->backend.buf[cpu].shmp);

			if (uatomic_read(&buf->active_readers)
			    && lib_ring_buffer_poll_deliver(config, buf,
					chan, handle)) {
				lib_ring_buffer_wakeup(buf, handle);
			}
		}
	} else {
		struct lttng_ust_lib_ring_buffer *buf =
			shmp(handle, chan->backend.buf[0].shmp);

		if (uatomic_read(&buf->active_readers)
		    && lib_ring_buffer_poll_deliver(config, buf,
				chan, handle)) {
			lib_ring_buffer_wakeup(buf, handle);
		}
	}
	pthread_mutex_unlock(&wakeup_fd_mutex);
}

static
void lib_ring_buffer_channel_read_timer(int sig, siginfo_t *si, void *uc)
{
	struct channel *chan;

	assert(CMM_LOAD_SHARED(timer_signal.tid) == pthread_self());
	chan = si->si_value.sival_ptr;
	DBG("Read timer for channel %p\n", chan);
	lib_ring_buffer_channel_do_read(chan);
	return;
}

static
void rb_setmask(sigset_t *mask)
{
	int ret;

	ret = sigemptyset(mask);
	if (ret) {
		PERROR("sigemptyset");
	}
	ret = sigaddset(mask, LTTNG_UST_RB_SIG_FLUSH);
	if (ret) {
		PERROR("sigaddset");
	}
	ret = sigaddset(mask, LTTNG_UST_RB_SIG_READ);
	if (ret) {
		PERROR("sigaddset");
	}
	ret = sigaddset(mask, LTTNG_UST_RB_SIG_TEARDOWN);
	if (ret) {
		PERROR("sigaddset");
	}
}

static
void *sig_thread(void *arg)
{
	sigset_t mask;
	siginfo_t info;
	int signr;

	/* Only self thread will receive signal mask. */
	rb_setmask(&mask);
	CMM_STORE_SHARED(timer_signal.tid, pthread_self());

	for (;;) {
		signr = sigwaitinfo(&mask, &info);
		if (signr == -1) {
			if (errno != EINTR)
				PERROR("sigwaitinfo");
			continue;
		}
		if (signr == LTTNG_UST_RB_SIG_FLUSH) {
			lib_ring_buffer_channel_switch_timer(info.si_signo,
					&info, NULL);
		} else if (signr == LTTNG_UST_RB_SIG_READ) {
			lib_ring_buffer_channel_read_timer(info.si_signo,
					&info, NULL);
		} else if (signr == LTTNG_UST_RB_SIG_TEARDOWN) {
			cmm_smp_mb();
			CMM_STORE_SHARED(timer_signal.qs_done, 1);
			cmm_smp_mb();
		} else {
			ERR("Unexptected signal %d\n", info.si_signo);
		}
	}
	return NULL;
}

/*
 * Ensure only a single thread listens on the timer signal.
 */
static
void lib_ring_buffer_setup_timer_thread(void)
{
	pthread_t thread;
	int ret;

	pthread_mutex_lock(&timer_signal.lock);
	if (timer_signal.setup_done)
		goto end;

	ret = pthread_create(&thread, NULL, &sig_thread, NULL);
	if (ret) {
		errno = ret;
		PERROR("pthread_create");
	}
	ret = pthread_detach(thread);
	if (ret) {
		errno = ret;
		PERROR("pthread_detach");
	}
	timer_signal.setup_done = 1;
end:
	pthread_mutex_unlock(&timer_signal.lock);
}

/*
 * Wait for signal-handling thread quiescent state.
 */
static
void lib_ring_buffer_wait_signal_thread_qs(unsigned int signr)
{
	sigset_t pending_set;
	int ret;

	/*
	 * We need to be the only thread interacting with the thread
	 * that manages signals for teardown synchronization.
	 */
	pthread_mutex_lock(&timer_signal.lock);

	/*
	 * Ensure we don't have any signal queued for this channel.
	 */
	for (;;) {
		ret = sigemptyset(&pending_set);
		if (ret == -1) {
			PERROR("sigemptyset");
		}
		ret = sigpending(&pending_set);
		if (ret == -1) {
			PERROR("sigpending");
		}
		if (!sigismember(&pending_set, signr))
			break;
		caa_cpu_relax();
	}

	/*
	 * From this point, no new signal handler will be fired that
	 * would try to access "chan". However, we still need to wait
	 * for any currently executing handler to complete.
	 */
	cmm_smp_mb();
	CMM_STORE_SHARED(timer_signal.qs_done, 0);
	cmm_smp_mb();

	/*
	 * Kill with LTTNG_UST_RB_SIG_TEARDOWN, so signal management
	 * thread wakes up.
	 */
	kill(getpid(), LTTNG_UST_RB_SIG_TEARDOWN);

	while (!CMM_LOAD_SHARED(timer_signal.qs_done))
		caa_cpu_relax();
	cmm_smp_mb();

	pthread_mutex_unlock(&timer_signal.lock);
}

static
void lib_ring_buffer_channel_switch_timer_start(struct channel *chan)
{
	struct sigevent sev;
	struct itimerspec its;
	int ret;

	if (!chan->switch_timer_interval || chan->switch_timer_enabled)
		return;

	chan->switch_timer_enabled = 1;

	lib_ring_buffer_setup_timer_thread();

	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = LTTNG_UST_RB_SIG_FLUSH;
	sev.sigev_value.sival_ptr = chan;
	ret = timer_create(CLOCKID, &sev, &chan->switch_timer);
	if (ret == -1) {
		PERROR("timer_create");
	}

	its.it_value.tv_sec = chan->switch_timer_interval / 1000000;
	its.it_value.tv_nsec = chan->switch_timer_interval % 1000000;
	its.it_interval.tv_sec = its.it_value.tv_sec;
	its.it_interval.tv_nsec = its.it_value.tv_nsec;

	ret = timer_settime(chan->switch_timer, 0, &its, NULL);
	if (ret == -1) {
		PERROR("timer_settime");
	}
}

static
void lib_ring_buffer_channel_switch_timer_stop(struct channel *chan)
{
	int ret;

	if (!chan->switch_timer_interval || !chan->switch_timer_enabled)
		return;

	ret = timer_delete(chan->switch_timer);
	if (ret == -1) {
		PERROR("timer_delete");
	}

	lib_ring_buffer_wait_signal_thread_qs(LTTNG_UST_RB_SIG_FLUSH);

	chan->switch_timer = 0;
	chan->switch_timer_enabled = 0;
}

static
void lib_ring_buffer_channel_read_timer_start(struct channel *chan)
{
	const struct lttng_ust_lib_ring_buffer_config *config = &chan->backend.config;
	struct sigevent sev;
	struct itimerspec its;
	int ret;

	if (config->wakeup != RING_BUFFER_WAKEUP_BY_TIMER
			|| !chan->read_timer_interval || chan->read_timer_enabled)
		return;

	chan->read_timer_enabled = 1;

	lib_ring_buffer_setup_timer_thread();

	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = LTTNG_UST_RB_SIG_READ;
	sev.sigev_value.sival_ptr = chan;
	ret = timer_create(CLOCKID, &sev, &chan->read_timer);
	if (ret == -1) {
		PERROR("timer_create");
	}

	its.it_value.tv_sec = chan->read_timer_interval / 1000000;
	its.it_value.tv_nsec = chan->read_timer_interval % 1000000;
	its.it_interval.tv_sec = its.it_value.tv_sec;
	its.it_interval.tv_nsec = its.it_value.tv_nsec;

	ret = timer_settime(chan->read_timer, 0, &its, NULL);
	if (ret == -1) {
		PERROR("timer_settime");
	}
}

static
void lib_ring_buffer_channel_read_timer_stop(struct channel *chan)
{
	const struct lttng_ust_lib_ring_buffer_config *config = &chan->backend.config;
	int ret;

	if (config->wakeup != RING_BUFFER_WAKEUP_BY_TIMER
			|| !chan->read_timer_interval || !chan->read_timer_enabled)
		return;

	ret = timer_delete(chan->read_timer);
	if (ret == -1) {
		PERROR("timer_delete");
	}

	/*
	 * do one more check to catch data that has been written in the last
	 * timer period.
	 */
	lib_ring_buffer_channel_do_read(chan);

	lib_ring_buffer_wait_signal_thread_qs(LTTNG_UST_RB_SIG_READ);

	chan->read_timer = 0;
	chan->read_timer_enabled = 0;
}

static void channel_unregister_notifiers(struct channel *chan,
			   struct lttng_ust_shm_handle *handle)
{
	lib_ring_buffer_channel_switch_timer_stop(chan);
	lib_ring_buffer_channel_read_timer_stop(chan);
}

static void channel_print_errors(struct channel *chan,
		struct lttng_ust_shm_handle *handle)
{
	const struct lttng_ust_lib_ring_buffer_config *config =
			&chan->backend.config;
	int cpu;

	if (config->alloc == RING_BUFFER_ALLOC_PER_CPU) {
		for_each_possible_cpu(cpu) {
			struct lttng_ust_lib_ring_buffer *buf =
				shmp(handle, chan->backend.buf[cpu].shmp);
			lib_ring_buffer_print_errors(chan, buf, cpu, handle);
		}
	} else {
		struct lttng_ust_lib_ring_buffer *buf =
			shmp(handle, chan->backend.buf[0].shmp);

		lib_ring_buffer_print_errors(chan, buf, -1, handle);
	}
}

static void channel_free(struct channel *chan,
		struct lttng_ust_shm_handle *handle)
{
	channel_backend_free(&chan->backend, handle);
	/* chan is freed by shm teardown */
	shm_object_table_destroy(handle->table);
	free(handle);
}

/**
 * channel_create - Create channel.
 * @config: ring buffer instance configuration
 * @name: name of the channel
 * @priv_data: ring buffer client private data area pointer (output)
 * @priv_data_size: length, in bytes, of the private data area.
 * @priv_data_init: initialization data for private data.
 * @buf_addr: pointer the the beginning of the preallocated buffer contiguous
 *            address mapping. It is used only by RING_BUFFER_STATIC
 *            configuration. It can be set to NULL for other backends.
 * @subbuf_size: subbuffer size
 * @num_subbuf: number of subbuffers
 * @switch_timer_interval: Time interval (in us) to fill sub-buffers with
 *                         padding to let readers get those sub-buffers.
 *                         Used for live streaming.
 * @read_timer_interval: Time interval (in us) to wake up pending readers.
 *
 * Holds cpu hotplug.
 * Returns NULL on failure.
 */
struct lttng_ust_shm_handle *channel_create(const struct lttng_ust_lib_ring_buffer_config *config,
		   const char *name,
		   void **priv_data,
		   size_t priv_data_align,
		   size_t priv_data_size,
		   void *priv_data_init,
		   void *buf_addr, size_t subbuf_size,
		   size_t num_subbuf, unsigned int switch_timer_interval,
		   unsigned int read_timer_interval)
{
	int ret;
	size_t shmsize, chansize;
	struct channel *chan;
	struct lttng_ust_shm_handle *handle;
	struct shm_object *shmobj;
	unsigned int nr_streams;

	if (config->alloc == RING_BUFFER_ALLOC_PER_CPU)
		nr_streams = num_possible_cpus();
	else
		nr_streams = 1;

	if (lib_ring_buffer_check_config(config, switch_timer_interval,
					 read_timer_interval))
		return NULL;

	handle = zmalloc(sizeof(struct lttng_ust_shm_handle));
	if (!handle)
		return NULL;

	/* Allocate table for channel + per-cpu buffers */
	handle->table = shm_object_table_create(1 + num_possible_cpus());
	if (!handle->table)
		goto error_table_alloc;

	/* Calculate the shm allocation layout */
	shmsize = sizeof(struct channel);
	shmsize += offset_align(shmsize, __alignof__(struct lttng_ust_lib_ring_buffer_shmp));
	shmsize += sizeof(struct lttng_ust_lib_ring_buffer_shmp) * nr_streams;
	chansize = shmsize;
	if (priv_data_align)
		shmsize += offset_align(shmsize, priv_data_align);
	shmsize += priv_data_size;

	/* Allocate normal memory for channel (not shared) */
	shmobj = shm_object_table_alloc(handle->table, shmsize, SHM_OBJECT_MEM);
	if (!shmobj)
		goto error_append;
	/* struct channel is at object 0, offset 0 (hardcoded) */
	set_shmp(handle->chan, zalloc_shm(shmobj, chansize));
	assert(handle->chan._ref.index == 0);
	assert(handle->chan._ref.offset == 0);
	chan = shmp(handle, handle->chan);
	if (!chan)
		goto error_append;
	chan->nr_streams = nr_streams;

	/* space for private data */
	if (priv_data_size) {
		DECLARE_SHMP(void, priv_data_alloc);

		align_shm(shmobj, priv_data_align);
		chan->priv_data_offset = shmobj->allocated_len;
		set_shmp(priv_data_alloc, zalloc_shm(shmobj, priv_data_size));
		if (!shmp(handle, priv_data_alloc))
			goto error_append;
		*priv_data = channel_get_private(chan);
		memcpy(*priv_data, priv_data_init, priv_data_size);
	} else {
		chan->priv_data_offset = -1;
		if (priv_data)
			*priv_data = NULL;
	}

	ret = channel_backend_init(&chan->backend, name, config,
				   subbuf_size, num_subbuf, handle);
	if (ret)
		goto error_backend_init;

	chan->handle = handle;
	chan->commit_count_mask = (~0UL >> chan->backend.num_subbuf_order);

	chan->switch_timer_interval = switch_timer_interval;
	chan->read_timer_interval = read_timer_interval;
	lib_ring_buffer_channel_switch_timer_start(chan);
	lib_ring_buffer_channel_read_timer_start(chan);

	return handle;

error_backend_init:
error_append:
	shm_object_table_destroy(handle->table);
error_table_alloc:
	free(handle);
	return NULL;
}

struct lttng_ust_shm_handle *channel_handle_create(void *data,
					uint64_t memory_map_size,
					int wakeup_fd)
{
	struct lttng_ust_shm_handle *handle;
	struct shm_object *object;

	handle = zmalloc(sizeof(struct lttng_ust_shm_handle));
	if (!handle)
		return NULL;

	/* Allocate table for channel + per-cpu buffers */
	handle->table = shm_object_table_create(1 + num_possible_cpus());
	if (!handle->table)
		goto error_table_alloc;
	/* Add channel object */
	object = shm_object_table_append_mem(handle->table, data,
			memory_map_size, wakeup_fd);
	if (!object)
		goto error_table_object;
	/* struct channel is at object 0, offset 0 (hardcoded) */
	handle->chan._ref.index = 0;
	handle->chan._ref.offset = 0;
	return handle;

error_table_object:
	shm_object_table_destroy(handle->table);
error_table_alloc:
	free(handle);
	return NULL;
}

int channel_handle_add_stream(struct lttng_ust_shm_handle *handle,
		int shm_fd, int wakeup_fd, uint32_t stream_nr,
		uint64_t memory_map_size)
{
	struct shm_object *object;

	/* Add stream object */
	object = shm_object_table_append_shm(handle->table,
			shm_fd, wakeup_fd, stream_nr,
			memory_map_size);
	if (!object)
		return -EINVAL;
	return 0;
}

unsigned int channel_handle_get_nr_streams(struct lttng_ust_shm_handle *handle)
{
	assert(handle->table);
	return handle->table->allocated_len - 1;
}

static
void channel_release(struct channel *chan, struct lttng_ust_shm_handle *handle)
{
	channel_free(chan, handle);
}

/**
 * channel_destroy - Finalize, wait for q.s. and destroy channel.
 * @chan: channel to destroy
 *
 * Holds cpu hotplug.
 * Call "destroy" callback, finalize channels, decrement the channel
 * reference count. Note that when readers have completed data
 * consumption of finalized channels, get_subbuf() will return -ENODATA.
 * They should release their handle at that point. 
 */
void channel_destroy(struct channel *chan, struct lttng_ust_shm_handle *handle,
		int consumer)
{
	if (consumer) {
		/*
		 * Note: the consumer takes care of finalizing and
		 * switching the buffers.
		 */
		channel_unregister_notifiers(chan, handle);
		/*
		 * The consumer prints errors.
		 */
		channel_print_errors(chan, handle);
	}

	/*
	 * sessiond/consumer are keeping a reference on the shm file
	 * descriptor directly. No need to refcount.
	 */
	channel_release(chan, handle);
	return;
}

struct lttng_ust_lib_ring_buffer *channel_get_ring_buffer(
					const struct lttng_ust_lib_ring_buffer_config *config,
					struct channel *chan, int cpu,
					struct lttng_ust_shm_handle *handle,
					int *shm_fd, int *wait_fd,
					int *wakeup_fd,
					uint64_t *memory_map_size)
{
	struct shm_ref *ref;

	if (config->alloc == RING_BUFFER_ALLOC_GLOBAL) {
		cpu = 0;
	} else {
		if (cpu >= num_possible_cpus())
			return NULL;
	}
	ref = &chan->backend.buf[cpu].shmp._ref;
	*shm_fd = shm_get_shm_fd(handle, ref);
	*wait_fd = shm_get_wait_fd(handle, ref);
	*wakeup_fd = shm_get_wakeup_fd(handle, ref);
	if (shm_get_shm_size(handle, ref, memory_map_size))
		return NULL;
	return shmp(handle, chan->backend.buf[cpu].shmp);
}

int ring_buffer_channel_close_wait_fd(const struct lttng_ust_lib_ring_buffer_config *config,
			struct channel *chan,
			struct lttng_ust_shm_handle *handle)
{
	struct shm_ref *ref;

	ref = &handle->chan._ref;
	return shm_close_wait_fd(handle, ref);
}

int ring_buffer_channel_close_wakeup_fd(const struct lttng_ust_lib_ring_buffer_config *config,
			struct channel *chan,
			struct lttng_ust_shm_handle *handle)
{
	struct shm_ref *ref;

	ref = &handle->chan._ref;
	return shm_close_wakeup_fd(handle, ref);
}

int ring_buffer_stream_close_wait_fd(const struct lttng_ust_lib_ring_buffer_config *config,
			struct channel *chan,
			struct lttng_ust_shm_handle *handle,
			int cpu)
{
	struct shm_ref *ref;

	if (config->alloc == RING_BUFFER_ALLOC_GLOBAL) {
		cpu = 0;
	} else {
		if (cpu >= num_possible_cpus())
			return -EINVAL;
	}
	ref = &chan->backend.buf[cpu].shmp._ref;
	return shm_close_wait_fd(handle, ref);
}

int ring_buffer_stream_close_wakeup_fd(const struct lttng_ust_lib_ring_buffer_config *config,
			struct channel *chan,
			struct lttng_ust_shm_handle *handle,
			int cpu)
{
	struct shm_ref *ref;
	int ret;

	if (config->alloc == RING_BUFFER_ALLOC_GLOBAL) {
		cpu = 0;
	} else {
		if (cpu >= num_possible_cpus())
			return -EINVAL;
	}
	ref = &chan->backend.buf[cpu].shmp._ref;
	pthread_mutex_lock(&wakeup_fd_mutex);
	ret = shm_close_wakeup_fd(handle, ref);
	pthread_mutex_unlock(&wakeup_fd_mutex);
	return ret;
}

int lib_ring_buffer_open_read(struct lttng_ust_lib_ring_buffer *buf,
			      struct lttng_ust_shm_handle *handle)
{
	if (uatomic_cmpxchg(&buf->active_readers, 0, 1) != 0)
		return -EBUSY;
	cmm_smp_mb();
	return 0;
}

void lib_ring_buffer_release_read(struct lttng_ust_lib_ring_buffer *buf,
				  struct lttng_ust_shm_handle *handle)
{
	struct channel *chan = shmp(handle, buf->backend.chan);

	CHAN_WARN_ON(chan, uatomic_read(&buf->active_readers) != 1);
	cmm_smp_mb();
	uatomic_dec(&buf->active_readers);
}

/**
 * lib_ring_buffer_snapshot - save subbuffer position snapshot (for read)
 * @buf: ring buffer
 * @consumed: consumed count indicating the position where to read
 * @produced: produced count, indicates position when to stop reading
 *
 * Returns -ENODATA if buffer is finalized, -EAGAIN if there is currently no
 * data to read at consumed position, or 0 if the get operation succeeds.
 */

int lib_ring_buffer_snapshot(struct lttng_ust_lib_ring_buffer *buf,
			     unsigned long *consumed, unsigned long *produced,
			     struct lttng_ust_shm_handle *handle)
{
	struct channel *chan = shmp(handle, buf->backend.chan);
	const struct lttng_ust_lib_ring_buffer_config *config = &chan->backend.config;
	unsigned long consumed_cur, write_offset;
	int finalized;

	finalized = CMM_ACCESS_ONCE(buf->finalized);
	/*
	 * Read finalized before counters.
	 */
	cmm_smp_rmb();
	consumed_cur = uatomic_read(&buf->consumed);
	/*
	 * No need to issue a memory barrier between consumed count read and
	 * write offset read, because consumed count can only change
	 * concurrently in overwrite mode, and we keep a sequence counter
	 * identifier derived from the write offset to check we are getting
	 * the same sub-buffer we are expecting (the sub-buffers are atomically
	 * "tagged" upon writes, tags are checked upon read).
	 */
	write_offset = v_read(config, &buf->offset);

	/*
	 * Check that we are not about to read the same subbuffer in
	 * which the writer head is.
	 */
	if (subbuf_trunc(write_offset, chan) - subbuf_trunc(consumed_cur, chan)
	    == 0)
		goto nodata;

	*consumed = consumed_cur;
	*produced = subbuf_trunc(write_offset, chan);

	return 0;

nodata:
	/*
	 * The memory barriers __wait_event()/wake_up_interruptible() take care
	 * of "raw_spin_is_locked" memory ordering.
	 */
	if (finalized)
		return -ENODATA;
	else
		return -EAGAIN;
}

/**
 * lib_ring_buffer_move_consumer - move consumed counter forward
 * @buf: ring buffer
 * @consumed_new: new consumed count value
 */
void lib_ring_buffer_move_consumer(struct lttng_ust_lib_ring_buffer *buf,
				   unsigned long consumed_new,
				   struct lttng_ust_shm_handle *handle)
{
	struct lttng_ust_lib_ring_buffer_backend *bufb = &buf->backend;
	struct channel *chan = shmp(handle, bufb->chan);
	unsigned long consumed;

	CHAN_WARN_ON(chan, uatomic_read(&buf->active_readers) != 1);

	/*
	 * Only push the consumed value forward.
	 * If the consumed cmpxchg fails, this is because we have been pushed by
	 * the writer in flight recorder mode.
	 */
	consumed = uatomic_read(&buf->consumed);
	while ((long) consumed - (long) consumed_new < 0)
		consumed = uatomic_cmpxchg(&buf->consumed, consumed,
					   consumed_new);
}

/**
 * lib_ring_buffer_get_subbuf - get exclusive access to subbuffer for reading
 * @buf: ring buffer
 * @consumed: consumed count indicating the position where to read
 *
 * Returns -ENODATA if buffer is finalized, -EAGAIN if there is currently no
 * data to read at consumed position, or 0 if the get operation succeeds.
 */
int lib_ring_buffer_get_subbuf(struct lttng_ust_lib_ring_buffer *buf,
			       unsigned long consumed,
			       struct lttng_ust_shm_handle *handle)
{
	struct channel *chan = shmp(handle, buf->backend.chan);
	const struct lttng_ust_lib_ring_buffer_config *config = &chan->backend.config;
	unsigned long consumed_cur, consumed_idx, commit_count, write_offset;
	int ret;
	int finalized;

retry:
	finalized = CMM_ACCESS_ONCE(buf->finalized);
	/*
	 * Read finalized before counters.
	 */
	cmm_smp_rmb();
	consumed_cur = uatomic_read(&buf->consumed);
	consumed_idx = subbuf_index(consumed, chan);
	commit_count = v_read(config, &shmp_index(handle, buf->commit_cold, consumed_idx)->cc_sb);
	/*
	 * Make sure we read the commit count before reading the buffer
	 * data and the write offset. Correct consumed offset ordering
	 * wrt commit count is insured by the use of cmpxchg to update
	 * the consumed offset.
	 */
	/*
	 * Local rmb to match the remote wmb to read the commit count
	 * before the buffer data and the write offset.
	 */
	cmm_smp_rmb();

	write_offset = v_read(config, &buf->offset);

	/*
	 * Check that the buffer we are getting is after or at consumed_cur
	 * position.
	 */
	if ((long) subbuf_trunc(consumed, chan)
	    - (long) subbuf_trunc(consumed_cur, chan) < 0)
		goto nodata;

	/*
	 * Check that the subbuffer we are trying to consume has been
	 * already fully committed.
	 */
	if (((commit_count - chan->backend.subbuf_size)
	     & chan->commit_count_mask)
	    - (buf_trunc(consumed, chan)
	       >> chan->backend.num_subbuf_order)
	    != 0)
		goto nodata;

	/*
	 * Check that we are not about to read the same subbuffer in
	 * which the writer head is.
	 */
	if (subbuf_trunc(write_offset, chan) - subbuf_trunc(consumed, chan)
	    == 0)
		goto nodata;

	/*
	 * Failure to get the subbuffer causes a busy-loop retry without going
	 * to a wait queue. These are caused by short-lived race windows where
	 * the writer is getting access to a subbuffer we were trying to get
	 * access to. Also checks that the "consumed" buffer count we are
	 * looking for matches the one contained in the subbuffer id.
	 */
	ret = update_read_sb_index(config, &buf->backend, &chan->backend,
				   consumed_idx, buf_trunc_val(consumed, chan),
				   handle);
	if (ret)
		goto retry;
	subbuffer_id_clear_noref(config, &buf->backend.buf_rsb.id);

	buf->get_subbuf_consumed = consumed;
	buf->get_subbuf = 1;

	return 0;

nodata:
	/*
	 * The memory barriers __wait_event()/wake_up_interruptible() take care
	 * of "raw_spin_is_locked" memory ordering.
	 */
	if (finalized)
		return -ENODATA;
	else
		return -EAGAIN;
}

/**
 * lib_ring_buffer_put_subbuf - release exclusive subbuffer access
 * @buf: ring buffer
 */
void lib_ring_buffer_put_subbuf(struct lttng_ust_lib_ring_buffer *buf,
				struct lttng_ust_shm_handle *handle)
{
	struct lttng_ust_lib_ring_buffer_backend *bufb = &buf->backend;
	struct channel *chan = shmp(handle, bufb->chan);
	const struct lttng_ust_lib_ring_buffer_config *config = &chan->backend.config;
	unsigned long read_sb_bindex, consumed_idx, consumed;

	CHAN_WARN_ON(chan, uatomic_read(&buf->active_readers) != 1);

	if (!buf->get_subbuf) {
		/*
		 * Reader puts a subbuffer it did not get.
		 */
		CHAN_WARN_ON(chan, 1);
		return;
	}
	consumed = buf->get_subbuf_consumed;
	buf->get_subbuf = 0;

	/*
	 * Clear the records_unread counter. (overruns counter)
	 * Can still be non-zero if a file reader simply grabbed the data
	 * without using iterators.
	 * Can be below zero if an iterator is used on a snapshot more than
	 * once.
	 */
	read_sb_bindex = subbuffer_id_get_index(config, bufb->buf_rsb.id);
	v_add(config, v_read(config,
			     &shmp(handle, shmp_index(handle, bufb->array, read_sb_bindex)->shmp)->records_unread),
	      &bufb->records_read);
	v_set(config, &shmp(handle, shmp_index(handle, bufb->array, read_sb_bindex)->shmp)->records_unread, 0);
	CHAN_WARN_ON(chan, config->mode == RING_BUFFER_OVERWRITE
		     && subbuffer_id_is_noref(config, bufb->buf_rsb.id));
	subbuffer_id_set_noref(config, &bufb->buf_rsb.id);

	/*
	 * Exchange the reader subbuffer with the one we put in its place in the
	 * writer subbuffer table. Expect the original consumed count. If
	 * update_read_sb_index fails, this is because the writer updated the
	 * subbuffer concurrently. We should therefore keep the subbuffer we
	 * currently have: it has become invalid to try reading this sub-buffer
	 * consumed count value anyway.
	 */
	consumed_idx = subbuf_index(consumed, chan);
	update_read_sb_index(config, &buf->backend, &chan->backend,
			     consumed_idx, buf_trunc_val(consumed, chan),
			     handle);
	/*
	 * update_read_sb_index return value ignored. Don't exchange sub-buffer
	 * if the writer concurrently updated it.
	 */
}

/*
 * cons_offset is an iterator on all subbuffer offsets between the reader
 * position and the writer position. (inclusive)
 */
static
void lib_ring_buffer_print_subbuffer_errors(struct lttng_ust_lib_ring_buffer *buf,
					    struct channel *chan,
					    unsigned long cons_offset,
					    int cpu,
					    struct lttng_ust_shm_handle *handle)
{
	const struct lttng_ust_lib_ring_buffer_config *config = &chan->backend.config;
	unsigned long cons_idx, commit_count, commit_count_sb;

	cons_idx = subbuf_index(cons_offset, chan);
	commit_count = v_read(config, &shmp_index(handle, buf->commit_hot, cons_idx)->cc);
	commit_count_sb = v_read(config, &shmp_index(handle, buf->commit_cold, cons_idx)->cc_sb);

	if (subbuf_offset(commit_count, chan) != 0)
		DBG("ring buffer %s, cpu %d: "
		       "commit count in subbuffer %lu,\n"
		       "expecting multiples of %lu bytes\n"
		       "  [ %lu bytes committed, %lu bytes reader-visible ]\n",
		       chan->backend.name, cpu, cons_idx,
		       chan->backend.subbuf_size,
		       commit_count, commit_count_sb);

	DBG("ring buffer: %s, cpu %d: %lu bytes committed\n",
	       chan->backend.name, cpu, commit_count);
}

static
void lib_ring_buffer_print_buffer_errors(struct lttng_ust_lib_ring_buffer *buf,
					 struct channel *chan,
					 void *priv, int cpu,
					 struct lttng_ust_shm_handle *handle)
{
	const struct lttng_ust_lib_ring_buffer_config *config = &chan->backend.config;
	unsigned long write_offset, cons_offset;

	/*
	 * No need to order commit_count, write_offset and cons_offset reads
	 * because we execute at teardown when no more writer nor reader
	 * references are left.
	 */
	write_offset = v_read(config, &buf->offset);
	cons_offset = uatomic_read(&buf->consumed);
	if (write_offset != cons_offset)
		DBG("ring buffer %s, cpu %d: "
		       "non-consumed data\n"
		       "  [ %lu bytes written, %lu bytes read ]\n",
		       chan->backend.name, cpu, write_offset, cons_offset);

	for (cons_offset = uatomic_read(&buf->consumed);
	     (long) (subbuf_trunc((unsigned long) v_read(config, &buf->offset),
				  chan)
		     - cons_offset) > 0;
	     cons_offset = subbuf_align(cons_offset, chan))
		lib_ring_buffer_print_subbuffer_errors(buf, chan, cons_offset,
						       cpu, handle);
}

static
void lib_ring_buffer_print_errors(struct channel *chan,
				struct lttng_ust_lib_ring_buffer *buf, int cpu,
				struct lttng_ust_shm_handle *handle)
{
	const struct lttng_ust_lib_ring_buffer_config *config = &chan->backend.config;
	void *priv = channel_get_private(chan);

	if (!strcmp(chan->backend.name, "relay-metadata-mmap")) {
		DBG("ring buffer %s: %lu records written, "
			"%lu records overrun\n",
			chan->backend.name,
			v_read(config, &buf->records_count),
			v_read(config, &buf->records_overrun));
	} else {
		DBG("ring buffer %s, cpu %d: %lu records written, "
			"%lu records overrun\n",
			chan->backend.name, cpu,
			v_read(config, &buf->records_count),
			v_read(config, &buf->records_overrun));

		if (v_read(config, &buf->records_lost_full)
		    || v_read(config, &buf->records_lost_wrap)
		    || v_read(config, &buf->records_lost_big))
			DBG("ring buffer %s, cpu %d: records were lost. Caused by:\n"
				"  [ %lu buffer full, %lu nest buffer wrap-around, "
				"%lu event too big ]\n",
				chan->backend.name, cpu,
				v_read(config, &buf->records_lost_full),
				v_read(config, &buf->records_lost_wrap),
				v_read(config, &buf->records_lost_big));
	}
	lib_ring_buffer_print_buffer_errors(buf, chan, priv, cpu, handle);
}

/*
 * lib_ring_buffer_switch_old_start: Populate old subbuffer header.
 *
 * Only executed when the buffer is finalized, in SWITCH_FLUSH.
 */
static
void lib_ring_buffer_switch_old_start(struct lttng_ust_lib_ring_buffer *buf,
				      struct channel *chan,
				      struct switch_offsets *offsets,
				      uint64_t tsc,
				      struct lttng_ust_shm_handle *handle)
{
	const struct lttng_ust_lib_ring_buffer_config *config = &chan->backend.config;
	unsigned long oldidx = subbuf_index(offsets->old, chan);
	unsigned long commit_count;

	config->cb.buffer_begin(buf, tsc, oldidx, handle);

	/*
	 * Order all writes to buffer before the commit count update that will
	 * determine that the subbuffer is full.
	 */
	cmm_smp_wmb();
	v_add(config, config->cb.subbuffer_header_size(),
	      &shmp_index(handle, buf->commit_hot, oldidx)->cc);
	commit_count = v_read(config, &shmp_index(handle, buf->commit_hot, oldidx)->cc);
	/* Check if the written buffer has to be delivered */
	lib_ring_buffer_check_deliver(config, buf, chan, offsets->old,
				      commit_count, oldidx, handle);
	lib_ring_buffer_write_commit_counter(config, buf, chan, oldidx,
					     offsets->old, commit_count,
					     config->cb.subbuffer_header_size(),
					     handle);
}

/*
 * lib_ring_buffer_switch_old_end: switch old subbuffer
 *
 * Note : offset_old should never be 0 here. It is ok, because we never perform
 * buffer switch on an empty subbuffer in SWITCH_ACTIVE mode. The caller
 * increments the offset_old value when doing a SWITCH_FLUSH on an empty
 * subbuffer.
 */
static
void lib_ring_buffer_switch_old_end(struct lttng_ust_lib_ring_buffer *buf,
				    struct channel *chan,
				    struct switch_offsets *offsets,
				    uint64_t tsc,
				    struct lttng_ust_shm_handle *handle)
{
	const struct lttng_ust_lib_ring_buffer_config *config = &chan->backend.config;
	unsigned long oldidx = subbuf_index(offsets->old - 1, chan);
	unsigned long commit_count, padding_size, data_size;

	data_size = subbuf_offset(offsets->old - 1, chan) + 1;
	padding_size = chan->backend.subbuf_size - data_size;
	subbuffer_set_data_size(config, &buf->backend, oldidx, data_size,
				handle);

	/*
	 * Order all writes to buffer before the commit count update that will
	 * determine that the subbuffer is full.
	 */
	cmm_smp_wmb();
	v_add(config, padding_size, &shmp_index(handle, buf->commit_hot, oldidx)->cc);
	commit_count = v_read(config, &shmp_index(handle, buf->commit_hot, oldidx)->cc);
	lib_ring_buffer_check_deliver(config, buf, chan, offsets->old - 1,
				      commit_count, oldidx, handle);
	lib_ring_buffer_write_commit_counter(config, buf, chan, oldidx,
					     offsets->old, commit_count,
					     padding_size, handle);
}

/*
 * lib_ring_buffer_switch_new_start: Populate new subbuffer.
 *
 * This code can be executed unordered : writers may already have written to the
 * sub-buffer before this code gets executed, caution.  The commit makes sure
 * that this code is executed before the deliver of this sub-buffer.
 */
static
void lib_ring_buffer_switch_new_start(struct lttng_ust_lib_ring_buffer *buf,
				      struct channel *chan,
				      struct switch_offsets *offsets,
				      uint64_t tsc,
				      struct lttng_ust_shm_handle *handle)
{
	const struct lttng_ust_lib_ring_buffer_config *config = &chan->backend.config;
	unsigned long beginidx = subbuf_index(offsets->begin, chan);
	unsigned long commit_count;

	config->cb.buffer_begin(buf, tsc, beginidx, handle);

	/*
	 * Order all writes to buffer before the commit count update that will
	 * determine that the subbuffer is full.
	 */
	cmm_smp_wmb();
	v_add(config, config->cb.subbuffer_header_size(),
	      &shmp_index(handle, buf->commit_hot, beginidx)->cc);
	commit_count = v_read(config, &shmp_index(handle, buf->commit_hot, beginidx)->cc);
	/* Check if the written buffer has to be delivered */
	lib_ring_buffer_check_deliver(config, buf, chan, offsets->begin,
				      commit_count, beginidx, handle);
	lib_ring_buffer_write_commit_counter(config, buf, chan, beginidx,
					     offsets->begin, commit_count,
					     config->cb.subbuffer_header_size(),
					     handle);
}

/*
 * lib_ring_buffer_switch_new_end: finish switching current subbuffer
 *
 * Calls subbuffer_set_data_size() to set the data size of the current
 * sub-buffer. We do not need to perform check_deliver nor commit here,
 * since this task will be done by the "commit" of the event for which
 * we are currently doing the space reservation.
 */
static
void lib_ring_buffer_switch_new_end(struct lttng_ust_lib_ring_buffer *buf,
				    struct channel *chan,
				    struct switch_offsets *offsets,
				    uint64_t tsc,
				    struct lttng_ust_shm_handle *handle)
{
	const struct lttng_ust_lib_ring_buffer_config *config = &chan->backend.config;
	unsigned long endidx, data_size;

	endidx = subbuf_index(offsets->end - 1, chan);
	data_size = subbuf_offset(offsets->end - 1, chan) + 1;
	subbuffer_set_data_size(config, &buf->backend, endidx, data_size,
				handle);
}

/*
 * Returns :
 * 0 if ok
 * !0 if execution must be aborted.
 */
static
int lib_ring_buffer_try_switch_slow(enum switch_mode mode,
				    struct lttng_ust_lib_ring_buffer *buf,
				    struct channel *chan,
				    struct switch_offsets *offsets,
				    uint64_t *tsc,
				    struct lttng_ust_shm_handle *handle)
{
	const struct lttng_ust_lib_ring_buffer_config *config = &chan->backend.config;
	unsigned long off, reserve_commit_diff;

	offsets->begin = v_read(config, &buf->offset);
	offsets->old = offsets->begin;
	offsets->switch_old_start = 0;
	off = subbuf_offset(offsets->begin, chan);

	*tsc = config->cb.ring_buffer_clock_read(chan);

	/*
	 * Ensure we flush the header of an empty subbuffer when doing the
	 * finalize (SWITCH_FLUSH). This ensures that we end up knowing the
	 * total data gathering duration even if there were no records saved
	 * after the last buffer switch.
	 * In SWITCH_ACTIVE mode, switch the buffer when it contains events.
	 * SWITCH_ACTIVE only flushes the current subbuffer, dealing with end of
	 * subbuffer header as appropriate.
	 * The next record that reserves space will be responsible for
	 * populating the following subbuffer header. We choose not to populate
	 * the next subbuffer header here because we want to be able to use
	 * SWITCH_ACTIVE for periodical buffer flush, which must
	 * guarantee that all the buffer content (records and header
	 * timestamps) are visible to the reader. This is required for
	 * quiescence guarantees for the fusion merge.
	 */
	if (mode != SWITCH_FLUSH && !off)
		return -1;	/* we do not have to switch : buffer is empty */

	if (caa_unlikely(off == 0)) {
		unsigned long sb_index, commit_count;

		/*
		 * We are performing a SWITCH_FLUSH. At this stage, there are no
		 * concurrent writes into the buffer.
		 *
		 * The client does not save any header information.  Don't
		 * switch empty subbuffer on finalize, because it is invalid to
		 * deliver a completely empty subbuffer.
		 */
		if (!config->cb.subbuffer_header_size())
			return -1;

		/* Test new buffer integrity */
		sb_index = subbuf_index(offsets->begin, chan);
		commit_count = v_read(config,
				&shmp_index(handle, buf->commit_cold,
					sb_index)->cc_sb);
		reserve_commit_diff =
		  (buf_trunc(offsets->begin, chan)
		   >> chan->backend.num_subbuf_order)
		  - (commit_count & chan->commit_count_mask);
		if (caa_likely(reserve_commit_diff == 0)) {
			/* Next subbuffer not being written to. */
			if (caa_unlikely(config->mode != RING_BUFFER_OVERWRITE &&
				subbuf_trunc(offsets->begin, chan)
				 - subbuf_trunc((unsigned long)
				     uatomic_read(&buf->consumed), chan)
				>= chan->backend.buf_size)) {
				/*
				 * We do not overwrite non consumed buffers
				 * and we are full : don't switch.
				 */
				return -1;
			} else {
				/*
				 * Next subbuffer not being written to, and we
				 * are either in overwrite mode or the buffer is
				 * not full. It's safe to write in this new
				 * subbuffer.
				 */
			}
		} else {
			/*
			 * Next subbuffer reserve offset does not match the
			 * commit offset. Don't perform switch in
			 * producer-consumer and overwrite mode.  Caused by
			 * either a writer OOPS or too many nested writes over a
			 * reserve/commit pair.
			 */
			return -1;
		}

		/*
		 * Need to write the subbuffer start header on finalize.
		 */
		offsets->switch_old_start = 1;
	}
	offsets->begin = subbuf_align(offsets->begin, chan);
	/* Note: old points to the next subbuf at offset 0 */
	offsets->end = offsets->begin;
	return 0;
}

/*
 * Force a sub-buffer switch. This operation is completely reentrant : can be
 * called while tracing is active with absolutely no lock held.
 *
 * Note, however, that as a v_cmpxchg is used for some atomic
 * operations, this function must be called from the CPU which owns the buffer
 * for a ACTIVE flush.
 */
void lib_ring_buffer_switch_slow(struct lttng_ust_lib_ring_buffer *buf, enum switch_mode mode,
				 struct lttng_ust_shm_handle *handle)
{
	struct channel *chan = shmp(handle, buf->backend.chan);
	const struct lttng_ust_lib_ring_buffer_config *config = &chan->backend.config;
	struct switch_offsets offsets;
	unsigned long oldidx;
	uint64_t tsc;

	offsets.size = 0;

	/*
	 * Perform retryable operations.
	 */
	do {
		if (lib_ring_buffer_try_switch_slow(mode, buf, chan, &offsets,
						    &tsc, handle))
			return;	/* Switch not needed */
	} while (v_cmpxchg(config, &buf->offset, offsets.old, offsets.end)
		 != offsets.old);

	/*
	 * Atomically update last_tsc. This update races against concurrent
	 * atomic updates, but the race will always cause supplementary full TSC
	 * records, never the opposite (missing a full TSC record when it would
	 * be needed).
	 */
	save_last_tsc(config, buf, tsc);

	/*
	 * Push the reader if necessary
	 */
	lib_ring_buffer_reserve_push_reader(buf, chan, offsets.old);

	oldidx = subbuf_index(offsets.old, chan);
	lib_ring_buffer_clear_noref(config, &buf->backend, oldidx, handle);

	/*
	 * May need to populate header start on SWITCH_FLUSH.
	 */
	if (offsets.switch_old_start) {
		lib_ring_buffer_switch_old_start(buf, chan, &offsets, tsc, handle);
		offsets.old += config->cb.subbuffer_header_size();
	}

	/*
	 * Switch old subbuffer.
	 */
	lib_ring_buffer_switch_old_end(buf, chan, &offsets, tsc, handle);
}

/*
 * Returns :
 * 0 if ok
 * -ENOSPC if event size is too large for packet.
 * -ENOBUFS if there is currently not enough space in buffer for the event.
 * -EIO if data cannot be written into the buffer for any other reason.
 */
static
int lib_ring_buffer_try_reserve_slow(struct lttng_ust_lib_ring_buffer *buf,
				     struct channel *chan,
				     struct switch_offsets *offsets,
				     struct lttng_ust_lib_ring_buffer_ctx *ctx)
{
	const struct lttng_ust_lib_ring_buffer_config *config = &chan->backend.config;
	struct lttng_ust_shm_handle *handle = ctx->handle;
	unsigned long reserve_commit_diff, offset_cmp;

retry:
	offsets->begin = offset_cmp = v_read(config, &buf->offset);
	offsets->old = offsets->begin;
	offsets->switch_new_start = 0;
	offsets->switch_new_end = 0;
	offsets->switch_old_end = 0;
	offsets->pre_header_padding = 0;

	ctx->tsc = config->cb.ring_buffer_clock_read(chan);
	if ((int64_t) ctx->tsc == -EIO)
		return -EIO;

	if (last_tsc_overflow(config, buf, ctx->tsc))
		ctx->rflags |= RING_BUFFER_RFLAG_FULL_TSC;

	if (caa_unlikely(subbuf_offset(offsets->begin, ctx->chan) == 0)) {
		offsets->switch_new_start = 1;		/* For offsets->begin */
	} else {
		offsets->size = config->cb.record_header_size(config, chan,
						offsets->begin,
						&offsets->pre_header_padding,
						ctx);
		offsets->size +=
			lib_ring_buffer_align(offsets->begin + offsets->size,
					      ctx->largest_align)
			+ ctx->data_size;
		if (caa_unlikely(subbuf_offset(offsets->begin, chan) +
			     offsets->size > chan->backend.subbuf_size)) {
			offsets->switch_old_end = 1;	/* For offsets->old */
			offsets->switch_new_start = 1;	/* For offsets->begin */
		}
	}
	if (caa_unlikely(offsets->switch_new_start)) {
		unsigned long sb_index, commit_count;

		/*
		 * We are typically not filling the previous buffer completely.
		 */
		if (caa_likely(offsets->switch_old_end))
			offsets->begin = subbuf_align(offsets->begin, chan);
		offsets->begin = offsets->begin
				 + config->cb.subbuffer_header_size();
		/* Test new buffer integrity */
		sb_index = subbuf_index(offsets->begin, chan);
		/*
		 * Read buf->offset before buf->commit_cold[sb_index].cc_sb.
		 * lib_ring_buffer_check_deliver() has the matching
		 * memory barriers required around commit_cold cc_sb
		 * updates to ensure reserve and commit counter updates
		 * are not seen reordered when updated by another CPU.
		 */
		cmm_smp_rmb();
		commit_count = v_read(config,
				&shmp_index(handle, buf->commit_cold,
					sb_index)->cc_sb);
		/* Read buf->commit_cold[sb_index].cc_sb before buf->offset. */
		cmm_smp_rmb();
		if (caa_unlikely(offset_cmp != v_read(config, &buf->offset))) {
			/*
			 * The reserve counter have been concurrently updated
			 * while we read the commit counter. This means the
			 * commit counter we read might not match buf->offset
			 * due to concurrent update. We therefore need to retry.
			 */
			goto retry;
		}
		reserve_commit_diff =
		  (buf_trunc(offsets->begin, chan)
		   >> chan->backend.num_subbuf_order)
		  - (commit_count & chan->commit_count_mask);
		if (caa_likely(reserve_commit_diff == 0)) {
			/* Next subbuffer not being written to. */
			if (caa_unlikely(config->mode != RING_BUFFER_OVERWRITE &&
				subbuf_trunc(offsets->begin, chan)
				 - subbuf_trunc((unsigned long)
				     uatomic_read(&buf->consumed), chan)
				>= chan->backend.buf_size)) {
				unsigned long nr_lost;

				/*
				 * We do not overwrite non consumed buffers
				 * and we are full : record is lost.
				 */
				nr_lost = v_read(config, &buf->records_lost_full);
				v_inc(config, &buf->records_lost_full);
				if ((nr_lost & (DBG_PRINT_NR_LOST - 1)) == 0) {
					DBG("%lu or more records lost in (%s:%d) (buffer full)\n",
						nr_lost + 1, chan->backend.name,
						buf->backend.cpu);
				}
				return -ENOBUFS;
			} else {
				/*
				 * Next subbuffer not being written to, and we
				 * are either in overwrite mode or the buffer is
				 * not full. It's safe to write in this new
				 * subbuffer.
				 */
			}
		} else {
			unsigned long nr_lost;

			/*
			 * Next subbuffer reserve offset does not match the
			 * commit offset, and this did not involve update to the
			 * reserve counter. Drop record in producer-consumer and
			 * overwrite mode. Caused by either a writer OOPS or too
			 * many nested writes over a reserve/commit pair.
			 */
			nr_lost = v_read(config, &buf->records_lost_wrap);
			v_inc(config, &buf->records_lost_wrap);
			if ((nr_lost & (DBG_PRINT_NR_LOST - 1)) == 0) {
				DBG("%lu or more records lost in (%s:%d) (wrap-around)\n",
					nr_lost + 1, chan->backend.name,
					buf->backend.cpu);
			}
			return -EIO;
		}
		offsets->size =
			config->cb.record_header_size(config, chan,
						offsets->begin,
						&offsets->pre_header_padding,
						ctx);
		offsets->size +=
			lib_ring_buffer_align(offsets->begin + offsets->size,
					      ctx->largest_align)
			+ ctx->data_size;
		if (caa_unlikely(subbuf_offset(offsets->begin, chan)
			     + offsets->size > chan->backend.subbuf_size)) {
			unsigned long nr_lost;

			/*
			 * Record too big for subbuffers, report error, don't
			 * complete the sub-buffer switch.
			 */
			nr_lost = v_read(config, &buf->records_lost_big);
			v_inc(config, &buf->records_lost_big);
			if ((nr_lost & (DBG_PRINT_NR_LOST - 1)) == 0) {
				DBG("%lu or more records lost in (%s:%d) record size "
					" of %zu bytes is too large for buffer\n",
					nr_lost + 1, chan->backend.name,
					buf->backend.cpu, offsets->size);
			}
			return -ENOSPC;
		} else {
			/*
			 * We just made a successful buffer switch and the
			 * record fits in the new subbuffer. Let's write.
			 */
		}
	} else {
		/*
		 * Record fits in the current buffer and we are not on a switch
		 * boundary. It's safe to write.
		 */
	}
	offsets->end = offsets->begin + offsets->size;

	if (caa_unlikely(subbuf_offset(offsets->end, chan) == 0)) {
		/*
		 * The offset_end will fall at the very beginning of the next
		 * subbuffer.
		 */
		offsets->switch_new_end = 1;	/* For offsets->begin */
	}
	return 0;
}

/**
 * lib_ring_buffer_reserve_slow - Atomic slot reservation in a buffer.
 * @ctx: ring buffer context.
 *
 * Return : -NOBUFS if not enough space, -ENOSPC if event size too large,
 * -EIO for other errors, else returns 0.
 * It will take care of sub-buffer switching.
 */
int lib_ring_buffer_reserve_slow(struct lttng_ust_lib_ring_buffer_ctx *ctx)
{
	struct channel *chan = ctx->chan;
	struct lttng_ust_shm_handle *handle = ctx->handle;
	const struct lttng_ust_lib_ring_buffer_config *config = &chan->backend.config;
	struct lttng_ust_lib_ring_buffer *buf;
	struct switch_offsets offsets;
	int ret;

	if (config->alloc == RING_BUFFER_ALLOC_PER_CPU)
		buf = shmp(handle, chan->backend.buf[ctx->cpu].shmp);
	else
		buf = shmp(handle, chan->backend.buf[0].shmp);
	ctx->buf = buf;

	offsets.size = 0;

	do {
		ret = lib_ring_buffer_try_reserve_slow(buf, chan, &offsets,
						       ctx);
		if (caa_unlikely(ret))
			return ret;
	} while (caa_unlikely(v_cmpxchg(config, &buf->offset, offsets.old,
				    offsets.end)
			  != offsets.old));

	/*
	 * Atomically update last_tsc. This update races against concurrent
	 * atomic updates, but the race will always cause supplementary full TSC
	 * records, never the opposite (missing a full TSC record when it would
	 * be needed).
	 */
	save_last_tsc(config, buf, ctx->tsc);

	/*
	 * Push the reader if necessary
	 */
	lib_ring_buffer_reserve_push_reader(buf, chan, offsets.end - 1);

	/*
	 * Clear noref flag for this subbuffer.
	 */
	lib_ring_buffer_clear_noref(config, &buf->backend,
				    subbuf_index(offsets.end - 1, chan),
				    handle);

	/*
	 * Switch old subbuffer if needed.
	 */
	if (caa_unlikely(offsets.switch_old_end)) {
		lib_ring_buffer_clear_noref(config, &buf->backend,
					    subbuf_index(offsets.old - 1, chan),
					    handle);
		lib_ring_buffer_switch_old_end(buf, chan, &offsets, ctx->tsc, handle);
	}

	/*
	 * Populate new subbuffer.
	 */
	if (caa_unlikely(offsets.switch_new_start))
		lib_ring_buffer_switch_new_start(buf, chan, &offsets, ctx->tsc, handle);

	if (caa_unlikely(offsets.switch_new_end))
		lib_ring_buffer_switch_new_end(buf, chan, &offsets, ctx->tsc, handle);

	ctx->slot_size = offsets.size;
	ctx->pre_offset = offsets.begin;
	ctx->buf_offset = offsets.begin + offsets.pre_header_padding;
	return 0;
}

/*
 * Force a read (imply TLS fixup for dlopen) of TLS variables.
 */
void lttng_fixup_ringbuffer_tls(void)
{
	asm volatile ("" : : "m" (URCU_TLS(lib_ring_buffer_nesting)));
}

void lib_ringbuffer_signal_init(void)
{
	sigset_t mask;
	int ret;

	/*
	 * Block signal for entire process, so only our thread processes
	 * it.
	 */
	rb_setmask(&mask);
	ret = pthread_sigmask(SIG_BLOCK, &mask, NULL);
	if (ret) {
		errno = ret;
		PERROR("pthread_sigmask");
	}
}
