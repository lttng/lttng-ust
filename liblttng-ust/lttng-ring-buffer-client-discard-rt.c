/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2010-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng lib ring buffer client (discard mode) for RT.
 */

#define _LGPL_SOURCE
#include "lttng-tracer.h"

#define RING_BUFFER_MODE_TEMPLATE		RING_BUFFER_DISCARD
#define RING_BUFFER_MODE_TEMPLATE_STRING	"discard-rt"
#define RING_BUFFER_MODE_TEMPLATE_INIT	\
	lttng_ring_buffer_client_discard_rt_init
#define RING_BUFFER_MODE_TEMPLATE_EXIT	\
	lttng_ring_buffer_client_discard_rt_exit
#define LTTNG_CLIENT_TYPE			LTTNG_CLIENT_DISCARD_RT
#define LTTNG_CLIENT_WAKEUP			RING_BUFFER_WAKEUP_BY_TIMER
#include "lttng-ring-buffer-client.h"
