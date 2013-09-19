#ifndef _LTTNG_RB_CLIENT_H
#define _LTTNG_RB_CLIENT_H

/*
 * Copyright (c) 2013 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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
 */

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
};

#endif /* _LTTNG_RB_CLIENT_H */
