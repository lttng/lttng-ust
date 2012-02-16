/*
 * ltt-ring-buffer-client-discard.c
 *
 * Copyright (C) 2010 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng lib ring buffer client (discard mode).
 *
 * Dual LGPL v2.1/GPL v2 license.
 */

#define _GNU_SOURCE
#include "ltt-tracer.h"

#define RING_BUFFER_MODE_TEMPLATE		RING_BUFFER_DISCARD
#define RING_BUFFER_MODE_TEMPLATE_STRING	"discard"
#define RING_BUFFER_MODE_TEMPLATE_INIT	\
	ltt_ring_buffer_client_discard_init
#define RING_BUFFER_MODE_TEMPLATE_EXIT	\
	ltt_ring_buffer_client_discard_exit
#define LTTNG_CLIENT_TYPE			LTTNG_CLIENT_DISCARD
#define LTTNG_CLIENT_CALLBACKS			lttng_client_callbacks_discard
#include "ltt-ring-buffer-client.h"
