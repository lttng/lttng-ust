/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2010-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng lib ring buffer client (overwrite mode).
 */

#define _LGPL_SOURCE
#include "common/tracer.h"
#include "common/ringbuffer-clients/clients.h"

#define RING_BUFFER_MODE_TEMPLATE		RING_BUFFER_OVERWRITE
#define RING_BUFFER_ALLOC_TEMPLATE		RING_BUFFER_ALLOC_PER_CPU
#define RING_BUFFER_MODE_TEMPLATE_STRING	"overwrite"
#define RING_BUFFER_MODE_TEMPLATE_ALLOC_TLS	\
	lttng_ust_ring_buffer_client_overwrite_alloc_tls
#define RING_BUFFER_MODE_TEMPLATE_INIT	\
	lttng_ring_buffer_client_overwrite_init
#define RING_BUFFER_MODE_TEMPLATE_EXIT	\
	lttng_ring_buffer_client_overwrite_exit
#define LTTNG_CLIENT_TYPE			LTTNG_CLIENT_OVERWRITE
#define LTTNG_CLIENT_WAKEUP			RING_BUFFER_WAKEUP_BY_WRITER
#include "common/ringbuffer-clients/template.h"
