/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2010-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng lib ring buffer metadta client.
 */

#define _LGPL_SOURCE
#include "common/tracer.h"

#define RING_BUFFER_MODE_TEMPLATE		RING_BUFFER_DISCARD
#define RING_BUFFER_MODE_TEMPLATE_STRING	"metadata"
#define RING_BUFFER_MODE_TEMPLATE_INIT	\
	lttng_ring_buffer_metadata_client_init
#define RING_BUFFER_MODE_TEMPLATE_EXIT	\
	lttng_ring_buffer_metadata_client_exit
#define LTTNG_CLIENT_TYPE			LTTNG_CLIENT_METADATA
#include "common/ringbuffer-clients/metadata-template.h"
