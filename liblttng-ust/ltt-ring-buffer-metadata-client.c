/*
 * ltt-ring-buffer-metadata-client.c
 *
 * Copyright (C) 2010 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng lib ring buffer metadta client.
 *
 * Dual LGPL v2.1/GPL v2 license.
 */

#include "ltt-tracer.h"

#define RING_BUFFER_MODE_TEMPLATE		RING_BUFFER_DISCARD
#define RING_BUFFER_MODE_TEMPLATE_STRING	"metadata"
#define RING_BUFFER_MODE_TEMPLATE_INIT	\
	ltt_ring_buffer_metadata_client_init
#define RING_BUFFER_MODE_TEMPLATE_EXIT	\
	ltt_ring_buffer_metadata_client_exit
#define LTTNG_CLIENT_TYPE			LTTNG_CLIENT_METADATA
#define LTTNG_CLIENT_CALLBACKS			lttng_client_callbacks_metadata
#include "ltt-ring-buffer-metadata-client.h"
