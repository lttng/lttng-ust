/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2010-2022 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng lib ring buffer client (overwrite mode, global buffers).
 */

#define _LGPL_SOURCE
#include "common/tracer.h"
#include "common/ringbuffer-clients/clients.h"

#define RING_BUFFER_MODE_TEMPLATE		RING_BUFFER_OVERWRITE
#define RING_BUFFER_ALLOC_TEMPLATE		RING_BUFFER_ALLOC_GLOBAL
#define RING_BUFFER_MODE_TEMPLATE_STRING	"overwrite-global"
#define RING_BUFFER_MODE_TEMPLATE_ALLOC_TLS	\
	lttng_ust_ring_buffer_client_overwrite_global_alloc_tls
#define RING_BUFFER_MODE_TEMPLATE_INIT	\
	lttng_ring_buffer_client_overwrite_global_init
#define RING_BUFFER_MODE_TEMPLATE_EXIT	\
	lttng_ring_buffer_client_overwrite_global_exit
#define LTTNG_CLIENT_TYPE			LTTNG_CLIENT_OVERWRITE_GLOBAL
#define LTTNG_CLIENT_WAKEUP			RING_BUFFER_WAKEUP_BY_WRITER
#include "common/ringbuffer-clients/template.h"
