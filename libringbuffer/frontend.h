#ifndef _LTTNG_RING_BUFFER_FRONTEND_H
#define _LTTNG_RING_BUFFER_FRONTEND_H

/*
 * libringbuffer/frontend.h
 *
 * Ring Buffer Library Synchronization Header (API).
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
 * Author:
 *	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * See ring_buffer_frontend.c for more information on wait-free algorithms.
 */

#include <urcu/compiler.h>
#include <urcu/uatomic.h>

#include "smp.h"
/* Internal helpers */
#include "frontend_internal.h"

/* Buffer creation/removal and setup operations */

/*
 * switch_timer_interval is the time interval (in us) to fill sub-buffers with
 * padding to let readers get those sub-buffers.  Used for live streaming.
 *
 * read_timer_interval is the time interval (in us) to wake up pending readers.
 *
 * buf_addr is a pointer the the beginning of the preallocated buffer contiguous
 * address mapping. It is used only by RING_BUFFER_STATIC configuration. It can
 * be set to NULL for other backends.
 *
 * priv_data (output) is set to a pointer into a "priv_data_len"-sized
 * memory area for client-specific data. This memory is managed by lib
 * ring buffer. priv_data_align is the alignment required for the
 * private data area.
 */

extern
struct lttng_ust_shm_handle *channel_create(const struct lttng_ust_lib_ring_buffer_config *config,
				const char *name,
				void **priv_data,
				size_t priv_data_align,
				size_t priv_data_size,
				void *priv_data_init,
				void *buf_addr,
				size_t subbuf_size, size_t num_subbuf,
				unsigned int switch_timer_interval,
				unsigned int read_timer_interval,
				const int *stream_fds, int nr_stream_fds,
				int64_t blocking_timeout);

/*
 * channel_destroy finalizes all channel's buffers, waits for readers to
 * release all references, and destroys the channel.
 */
extern
void channel_destroy(struct channel *chan, struct lttng_ust_shm_handle *handle,
		int consumer);


/* Buffer read operations */

/*
 * Iteration on channel cpumask needs to issue a read barrier to match the write
 * barrier in cpu hotplug. It orders the cpumask read before read of per-cpu
 * buffer data. The per-cpu buffer is never removed by cpu hotplug; teardown is
 * only performed at channel destruction.
 */
#define for_each_channel_cpu(cpu, chan)					\
	for_each_possible_cpu(cpu)

extern struct lttng_ust_lib_ring_buffer *channel_get_ring_buffer(
				const struct lttng_ust_lib_ring_buffer_config *config,
				struct channel *chan, int cpu,
				struct lttng_ust_shm_handle *handle,
				int *shm_fd, int *wait_fd,
				int *wakeup_fd,
				uint64_t *memory_map_size);
extern
int ring_buffer_channel_close_wait_fd(const struct lttng_ust_lib_ring_buffer_config *config,
			struct channel *chan,
			struct lttng_ust_shm_handle *handle);
extern
int ring_buffer_channel_close_wakeup_fd(const struct lttng_ust_lib_ring_buffer_config *config,
			struct channel *chan,
			struct lttng_ust_shm_handle *handle);
extern
int ring_buffer_stream_close_wait_fd(const struct lttng_ust_lib_ring_buffer_config *config,
		struct channel *chan,
		struct lttng_ust_shm_handle *handle,
		int cpu);
extern
int ring_buffer_stream_close_wakeup_fd(const struct lttng_ust_lib_ring_buffer_config *config,
		struct channel *chan,
		struct lttng_ust_shm_handle *handle,
		int cpu);

extern int lib_ring_buffer_open_read(struct lttng_ust_lib_ring_buffer *buf,
				     struct lttng_ust_shm_handle *handle);
extern void lib_ring_buffer_release_read(struct lttng_ust_lib_ring_buffer *buf,
					 struct lttng_ust_shm_handle *handle);

/*
 * Initialize signals for ring buffer. Should be called early e.g. by
 * main() in the program to affect all threads.
 */
void lib_ringbuffer_signal_init(void);

/*
 * Read sequence: snapshot, many get_subbuf/put_subbuf, move_consumer.
 */
extern int lib_ring_buffer_snapshot(struct lttng_ust_lib_ring_buffer *buf,
				    unsigned long *consumed,
				    unsigned long *produced,
				    struct lttng_ust_shm_handle *handle);
extern int lib_ring_buffer_snapshot_sample_positions(
				    struct lttng_ust_lib_ring_buffer *buf,
				    unsigned long *consumed,
				    unsigned long *produced,
				    struct lttng_ust_shm_handle *handle);
extern void lib_ring_buffer_move_consumer(struct lttng_ust_lib_ring_buffer *buf,
					  unsigned long consumed_new,
					  struct lttng_ust_shm_handle *handle);

extern int lib_ring_buffer_get_subbuf(struct lttng_ust_lib_ring_buffer *buf,
				      unsigned long consumed,
				      struct lttng_ust_shm_handle *handle);
extern void lib_ring_buffer_put_subbuf(struct lttng_ust_lib_ring_buffer *buf,
				       struct lttng_ust_shm_handle *handle);

/*
 * lib_ring_buffer_get_next_subbuf/lib_ring_buffer_put_next_subbuf are helpers
 * to read sub-buffers sequentially.
 */
static inline int lib_ring_buffer_get_next_subbuf(struct lttng_ust_lib_ring_buffer *buf,
						  struct lttng_ust_shm_handle *handle)
{
	int ret;

	ret = lib_ring_buffer_snapshot(buf, &buf->cons_snapshot,
				       &buf->prod_snapshot, handle);
	if (ret)
		return ret;
	ret = lib_ring_buffer_get_subbuf(buf, buf->cons_snapshot, handle);
	return ret;
}

static inline
void lib_ring_buffer_put_next_subbuf(struct lttng_ust_lib_ring_buffer *buf,
				     struct lttng_ust_shm_handle *handle)
{
	struct channel *chan;

	chan = shmp(handle, buf->backend.chan);
	if (!chan)
		return;
	lib_ring_buffer_put_subbuf(buf, handle);
	lib_ring_buffer_move_consumer(buf, subbuf_align(buf->cons_snapshot, chan),
			handle);
}

extern void channel_reset(struct channel *chan);
extern void lib_ring_buffer_reset(struct lttng_ust_lib_ring_buffer *buf,
				  struct lttng_ust_shm_handle *handle);

static inline
unsigned long lib_ring_buffer_get_offset(const struct lttng_ust_lib_ring_buffer_config *config,
					 struct lttng_ust_lib_ring_buffer *buf)
{
	return v_read(config, &buf->offset);
}

static inline
unsigned long lib_ring_buffer_get_consumed(const struct lttng_ust_lib_ring_buffer_config *config,
					   struct lttng_ust_lib_ring_buffer *buf)
{
	return uatomic_read(&buf->consumed);
}

/*
 * Must call lib_ring_buffer_is_finalized before reading counters (memory
 * ordering enforced with respect to trace teardown).
 */
static inline
int lib_ring_buffer_is_finalized(const struct lttng_ust_lib_ring_buffer_config *config,
				 struct lttng_ust_lib_ring_buffer *buf)
{
	int finalized = CMM_ACCESS_ONCE(buf->finalized);
	/*
	 * Read finalized before counters.
	 */
	cmm_smp_rmb();
	return finalized;
}

static inline
int lib_ring_buffer_channel_is_finalized(const struct channel *chan)
{
	return chan->finalized;
}

static inline
int lib_ring_buffer_channel_is_disabled(const struct channel *chan)
{
	return uatomic_read(&chan->record_disabled);
}

static inline
unsigned long lib_ring_buffer_get_read_data_size(
				const struct lttng_ust_lib_ring_buffer_config *config,
				struct lttng_ust_lib_ring_buffer *buf,
				struct lttng_ust_shm_handle *handle)
{
	return subbuffer_get_read_data_size(config, &buf->backend, handle);
}

static inline
unsigned long lib_ring_buffer_get_records_count(
				const struct lttng_ust_lib_ring_buffer_config *config,
				struct lttng_ust_lib_ring_buffer *buf)
{
	return v_read(config, &buf->records_count);
}

static inline
unsigned long lib_ring_buffer_get_records_overrun(
				const struct lttng_ust_lib_ring_buffer_config *config,
				struct lttng_ust_lib_ring_buffer *buf)
{
	return v_read(config, &buf->records_overrun);
}

static inline
unsigned long lib_ring_buffer_get_records_lost_full(
				const struct lttng_ust_lib_ring_buffer_config *config,
				struct lttng_ust_lib_ring_buffer *buf)
{
	return v_read(config, &buf->records_lost_full);
}

static inline
unsigned long lib_ring_buffer_get_records_lost_wrap(
				const struct lttng_ust_lib_ring_buffer_config *config,
				struct lttng_ust_lib_ring_buffer *buf)
{
	return v_read(config, &buf->records_lost_wrap);
}

static inline
unsigned long lib_ring_buffer_get_records_lost_big(
				const struct lttng_ust_lib_ring_buffer_config *config,
				struct lttng_ust_lib_ring_buffer *buf)
{
	return v_read(config, &buf->records_lost_big);
}

static inline
unsigned long lib_ring_buffer_get_records_read(
				const struct lttng_ust_lib_ring_buffer_config *config,
				struct lttng_ust_lib_ring_buffer *buf)
{
	return v_read(config, &buf->backend.records_read);
}

#endif /* _LTTNG_RING_BUFFER_FRONTEND_H */
