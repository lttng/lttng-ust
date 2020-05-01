/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2013 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _LTTNG_RB_CLIENT_H
#define _LTTNG_RB_CLIENT_H

#include <stdint.h>

struct lttng_ust_client_lib_ring_buffer_client_cb {
	struct lttng_ust_lib_ring_buffer_client_cb parent;

	int (*timestamp_begin) (struct lttng_ust_lib_ring_buffer *buf,
			struct lttng_ust_shm_handle *handle,
			uint64_t *timestamp_begin);
	int (*timestamp_end) (struct lttng_ust_lib_ring_buffer *buf,
			struct lttng_ust_shm_handle *handle,
			uint64_t *timestamp_end);
	int (*events_discarded) (struct lttng_ust_lib_ring_buffer *buf,
			struct lttng_ust_shm_handle *handle,
			uint64_t *events_discarded);
	int (*content_size) (struct lttng_ust_lib_ring_buffer *buf,
			struct lttng_ust_shm_handle *handle,
			uint64_t *content_size);
	int (*packet_size) (struct lttng_ust_lib_ring_buffer *buf,
			struct lttng_ust_shm_handle *handle,
			uint64_t *packet_size);
	int (*stream_id) (struct lttng_ust_lib_ring_buffer *buf,
			struct lttng_ust_shm_handle *handle,
			uint64_t *stream_id);
	int (*current_timestamp) (struct lttng_ust_lib_ring_buffer *buf,
			struct lttng_ust_shm_handle *handle,
			uint64_t *ts);
	int (*sequence_number) (struct lttng_ust_lib_ring_buffer *buf,
		struct lttng_ust_shm_handle *handle, uint64_t *seq);
	int (*instance_id) (struct lttng_ust_lib_ring_buffer *buf,
			struct lttng_ust_shm_handle *handle, uint64_t *id);
};

#endif /* _LTTNG_RB_CLIENT_H */
