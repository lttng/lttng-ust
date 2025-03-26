/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include "common/ringbuffer-clients/clients.h"

void lttng_ust_ring_buffer_clients_init(void)
{
	lttng_ring_buffer_metadata_client_init();
	lttng_ring_buffer_client_overwrite_init();
	lttng_ring_buffer_client_overwrite_rt_init();
	lttng_ring_buffer_client_discard_init();
	lttng_ring_buffer_client_discard_rt_init();
	lttng_ring_buffer_client_overwrite_per_channel_init();
	lttng_ring_buffer_client_overwrite_per_channel_rt_init();
	lttng_ring_buffer_client_discard_per_channel_init();
	lttng_ring_buffer_client_discard_per_channel_rt_init();
}

void lttng_ust_ring_buffer_clients_exit(void)
{
	lttng_ring_buffer_client_discard_per_channel_rt_exit();
	lttng_ring_buffer_client_discard_per_channel_exit();
	lttng_ring_buffer_client_overwrite_per_channel_rt_exit();
	lttng_ring_buffer_client_overwrite_per_channel_exit();
	lttng_ring_buffer_client_discard_rt_exit();
	lttng_ring_buffer_client_discard_exit();
	lttng_ring_buffer_client_overwrite_rt_exit();
	lttng_ring_buffer_client_overwrite_exit();
	lttng_ring_buffer_metadata_client_exit();
}
