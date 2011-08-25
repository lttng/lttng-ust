/*
 * ltt-ring-buffer-client-overwrite.c
 *
 * Copyright (C) 2010 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng lib ring buffer client (overwrite mode).
 *
 * Dual LGPL v2.1/GPL v2 license.
 */

#include "ltt-tracer.h"

#define RING_BUFFER_MODE_TEMPLATE		RING_BUFFER_OVERWRITE
#define RING_BUFFER_MODE_TEMPLATE_STRING	"overwrite"
#define RING_BUFFER_MODE_TEMPLATE_INIT	\
	ltt_ring_buffer_client_overwrite_init
#define RING_BUFFER_MODE_TEMPLATE_EXIT	\
	ltt_ring_buffer_client_overwrite_exit
#include "ltt-ring-buffer-client.h"
