/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2010-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng lib ring buffer client (discard mode).
 */

#define _LGPL_SOURCE
#include "lttng-tracer.h"
#include "lttng-rb-clients.h"

#define RING_BUFFER_MODE_TEMPLATE		RING_BUFFER_DISCARD
#define RING_BUFFER_MODE_TEMPLATE_STRING	"discard"
#define RING_BUFFER_MODE_TEMPLATE_ALLOC_TLS	\
	lttng_ust_ring_buffer_client_discard_alloc_tls
#define RING_BUFFER_MODE_TEMPLATE_INIT	\
	lttng_ring_buffer_client_discard_init
#define RING_BUFFER_MODE_TEMPLATE_EXIT	\
	lttng_ring_buffer_client_discard_exit
#define LTTNG_CLIENT_TYPE			LTTNG_CLIENT_DISCARD
#define LTTNG_CLIENT_WAKEUP			RING_BUFFER_WAKEUP_BY_WRITER
#include "lttng-ring-buffer-client-template.h"
