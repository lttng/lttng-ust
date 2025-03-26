/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2010-2021 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Ring buffer configuration header. Note: after declaring the standard inline
 * functions, clients should also include linux/ringbuffer/api.h.
 */

#ifndef _LTTNG_RING_BUFFER_CONFIG_H
#define _LTTNG_RING_BUFFER_CONFIG_H

#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <urcu/arch.h>
#include <string.h>

#include <lttng/ust-utils.h>
#include <lttng/ust-compiler.h>
#include <lttng/ust-tracer.h>

struct lttng_ust_ring_buffer;
struct lttng_ust_ring_buffer_channel;
struct lttng_ust_ring_buffer_config;
struct lttng_ust_ring_buffer_ctx_private;
struct lttng_ust_shm_handle;

/*
 * Ring buffer client callbacks. Only used by slow path, never on fast path.
 * For the fast path, record_header_size(), ring_buffer_clock_read() should be
 * provided as inline functions too.  These may simply return 0 if not used by
 * the client.
 */
struct lttng_ust_ring_buffer_client_cb {
	/* Mandatory callbacks */

	/* A static inline version is also required for fast path */
	uint64_t (*ring_buffer_clock_read) (struct lttng_ust_ring_buffer_channel *chan);
	size_t (*record_header_size) (const struct lttng_ust_ring_buffer_config *config,
				      struct lttng_ust_ring_buffer_channel *chan,
				      size_t offset,
				      size_t *pre_header_padding,
				      struct lttng_ust_ring_buffer_ctx *ctx,
				      void *client_ctx);

	/* Slow path only, at subbuffer switch */
	size_t (*subbuffer_header_size) (void);
	void (*buffer_begin) (struct lttng_ust_ring_buffer *buf, uint64_t timestamp,
			      unsigned int subbuf_idx,
			      struct lttng_ust_shm_handle *handle);
	void (*buffer_end) (struct lttng_ust_ring_buffer *buf, uint64_t timestamp,
			    unsigned int subbuf_idx, unsigned long data_size,
			    struct lttng_ust_shm_handle *handle,
			    const struct lttng_ust_ring_buffer_ctx *ctx);

	/* Optional callbacks (can be set to NULL) */

	/* Called at buffer creation/finalize */
	int (*buffer_create) (struct lttng_ust_ring_buffer *buf, void *priv,
			      int cpu, const char *name,
			      struct lttng_ust_shm_handle *handle);
	/*
	 * Clients should guarantee that no new reader handle can be opened
	 * after finalize.
	 */
	void (*buffer_finalize) (struct lttng_ust_ring_buffer *buf,
				 void *priv, int cpu,
				 struct lttng_ust_shm_handle *handle);

	/*
	 * Extract header length, payload length and timestamp from event
	 * record. Used by buffer iterators. Timestamp is only used by channel
	 * iterator.
	 */
	void (*record_get) (const struct lttng_ust_ring_buffer_config *config,
			    struct lttng_ust_ring_buffer_channel *chan,
			    struct lttng_ust_ring_buffer *buf,
			    size_t offset, size_t *header_len,
			    size_t *payload_len, uint64_t *timestamp,
			    struct lttng_ust_shm_handle *handle);
	/*
	 * Offset and size of content size field in client.
	 */
	void (*content_size_field) (const struct lttng_ust_ring_buffer_config *config,
				size_t *offset, size_t *length);
	void (*packet_size_field) (const struct lttng_ust_ring_buffer_config *config,
				size_t *offset, size_t *length);
};

/*
 * Ring buffer instance configuration.
 *
 * Declare as "static const" within the client object to ensure the inline fast
 * paths can be optimized.
 *
 * alloc/sync pairs:
 *
 * RING_BUFFER_ALLOC_PER_CPU and RING_BUFFER_SYNC_PER_CPU :
 *   Per-cpu buffers with per-cpu synchronization.
 *
 * RING_BUFFER_ALLOC_PER_CPU and RING_BUFFER_SYNC_PER_CHANNEL :
 *   Per-cpu buffer with per-channel synchronization. Tracing can be performed with
 *   preemption enabled, statistically stays on the local buffers.
 *
 * RING_BUFFER_ALLOC_PER_CHANNEL and RING_BUFFER_SYNC_PER_CPU :
 *   Should only be used for buffers belonging to a single thread or protected
 *   by mutual exclusion by the client. Note that periodical sub-buffer switch
 *   should be disabled in this kind of configuration.
 *
 * RING_BUFFER_ALLOC_PER_CHANNEL and RING_BUFFER_SYNC_PER_CHANNEL :
 *   Per-channel shared buffer with per-channel synchronization.
 *
 * wakeup:
 *
 * RING_BUFFER_WAKEUP_BY_TIMER uses per-cpu deferrable timers to poll the
 * buffers and wake up readers if data is ready. Mainly useful for tracers which
 * don't want to call into the wakeup code on the tracing path. Use in
 * combination with "read_timer_interval" channel_create() argument.
 *
 * RING_BUFFER_WAKEUP_BY_WRITER directly wakes up readers when a subbuffer is
 * ready to read. Lower latencies before the reader is woken up. Mainly suitable
 * for drivers.
 *
 * RING_BUFFER_WAKEUP_NONE does not perform any wakeup whatsoever. The client
 * has the responsibility to perform wakeups.
 */
#define LTTNG_UST_RING_BUFFER_CONFIG_PADDING	20

enum lttng_ust_ring_buffer_alloc_types {
	RING_BUFFER_ALLOC_PER_CPU,
	RING_BUFFER_ALLOC_PER_CHANNEL,
};

enum lttng_ust_ring_buffer_sync_types {
	RING_BUFFER_SYNC_PER_CPU,	/* Wait-free */
	RING_BUFFER_SYNC_PER_CHANNEL,	/* Lock-free */
};

enum lttng_ust_ring_buffer_mode_types {
	RING_BUFFER_OVERWRITE = 0,	/* Overwrite when buffer full */
	RING_BUFFER_DISCARD = 1,	/* Discard when buffer full */
};

enum lttng_ust_ring_buffer_output_types {
	RING_BUFFER_SPLICE,
	RING_BUFFER_MMAP,
	RING_BUFFER_READ,		/* TODO */
	RING_BUFFER_ITERATOR,
	RING_BUFFER_NONE,
};

enum lttng_ust_ring_buffer_backend_types {
	RING_BUFFER_PAGE,
	RING_BUFFER_VMAP,		/* TODO */
	RING_BUFFER_STATIC,		/* TODO */
};

enum lttng_ust_ring_buffer_oops_types {
	RING_BUFFER_NO_OOPS_CONSISTENCY,
	RING_BUFFER_OOPS_CONSISTENCY,
};

enum lttng_ust_ring_buffer_ipi_types {
	RING_BUFFER_IPI_BARRIER,
	RING_BUFFER_NO_IPI_BARRIER,
};

enum lttng_ust_ring_buffer_wakeup_types {
	RING_BUFFER_WAKEUP_BY_TIMER,	/* wake up performed by timer */
	RING_BUFFER_WAKEUP_BY_WRITER,	/*
					 * writer wakes up reader,
					 * not lock-free
					 * (takes spinlock).
					 */
};

struct lttng_ust_ring_buffer_config {
	enum lttng_ust_ring_buffer_alloc_types alloc;
	enum lttng_ust_ring_buffer_sync_types sync;
	enum lttng_ust_ring_buffer_mode_types mode;
	enum lttng_ust_ring_buffer_output_types output;
	enum lttng_ust_ring_buffer_backend_types backend;
	enum lttng_ust_ring_buffer_oops_types oops;
	enum lttng_ust_ring_buffer_ipi_types ipi;
	enum lttng_ust_ring_buffer_wakeup_types wakeup;
	/*
	 * timestamp_bits: timestamp bits saved at each record.
	 *   0 and 64 disable the timestamp compression scheme.
	 */
	unsigned int timestamp_bits;
	struct lttng_ust_ring_buffer_client_cb cb;
	/*
	 * client_type is used by the consumer process (which is in a
	 * different address space) to lookup the appropriate client
	 * callbacks and update the cb pointers.
	 */
	int client_type;
	int _unused1;
	const struct lttng_ust_ring_buffer_client_cb *cb_ptr;
	char padding[LTTNG_UST_RING_BUFFER_CONFIG_PADDING];
};

/*
 * Reservation flags.
 *
 * RING_BUFFER_RFLAG_FULL_TIMESTAMP
 *
 * This flag is passed to record_header_size() and to the primitive used to
 * write the record header. It indicates that the full 64-bit time value is
 * needed in the record header. If this flag is not set, the record header needs
 * only to contain "timestamp_bits" bit of time value.
 *
 * Reservation flags can be added by the client, starting from
 * "(RING_BUFFER_FLAGS_END << 0)". It can be used to pass information from
 * record_header_size() to lib_ring_buffer_write_record_header().
 */
#define	RING_BUFFER_RFLAG_FULL_TIMESTAMP	(1U << 0)
#define RING_BUFFER_RFLAG_END			(1U << 1)

/*
 * lib_ring_buffer_check_config() returns 0 on success.
 * Used internally to check for valid configurations at channel creation.
 */
static inline
int lib_ring_buffer_check_config(const struct lttng_ust_ring_buffer_config *config,
			     unsigned int switch_timer_interval,
			     unsigned int read_timer_interval)
	lttng_ust_notrace;

static inline
int lib_ring_buffer_check_config(const struct lttng_ust_ring_buffer_config *config,
			     unsigned int switch_timer_interval,
			     unsigned int read_timer_interval __attribute__((unused)))
{
	if (config->alloc == RING_BUFFER_ALLOC_PER_CHANNEL
	    && config->sync == RING_BUFFER_SYNC_PER_CPU
	    && switch_timer_interval)
		return -EINVAL;
	return 0;
}

#endif /* _LTTNG_RING_BUFFER_CONFIG_H */
