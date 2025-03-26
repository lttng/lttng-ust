/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2010-2022 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng lib ring buffer client (discard mode, global buffers) for RT.
 */

#define _LGPL_SOURCE
#include "common/tracer.h"
#include "common/ringbuffer-clients/clients.h"

#define RING_BUFFER_MODE_TEMPLATE		RING_BUFFER_DISCARD
#define RING_BUFFER_ALLOC_TEMPLATE		RING_BUFFER_ALLOC_GLOBAL
#define RING_BUFFER_MODE_TEMPLATE_STRING	"discard-global-rt"
#define RING_BUFFER_MODE_TEMPLATE_ALLOC_TLS	\
	lttng_ust_ring_buffer_client_discard_global_rt_alloc_tls
#define RING_BUFFER_MODE_TEMPLATE_INIT	\
	lttng_ring_buffer_client_discard_global_rt_init
#define RING_BUFFER_MODE_TEMPLATE_EXIT	\
	lttng_ring_buffer_client_discard_global_rt_exit
#define LTTNG_CLIENT_TYPE			LTTNG_CLIENT_DISCARD_GLOBAL_RT
#define LTTNG_CLIENT_WAKEUP			RING_BUFFER_WAKEUP_BY_TIMER
#include "common/ringbuffer-clients/template.h"
