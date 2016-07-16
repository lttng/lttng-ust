/*
 * lttng-ring-buffer-metadata-client.c
 *
 * LTTng lib ring buffer metadta client.
 *
 * Copyright (C) 2010-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; only
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#define _GNU_SOURCE
#define _LGPL_SOURCE
#include "lttng-tracer.h"

#define RING_BUFFER_MODE_TEMPLATE		RING_BUFFER_DISCARD
#define RING_BUFFER_MODE_TEMPLATE_STRING	"metadata"
#define RING_BUFFER_MODE_TEMPLATE_INIT	\
	lttng_ring_buffer_metadata_client_init
#define RING_BUFFER_MODE_TEMPLATE_EXIT	\
	lttng_ring_buffer_metadata_client_exit
#define LTTNG_CLIENT_TYPE			LTTNG_CLIENT_METADATA
#define LTTNG_CLIENT_CALLBACKS			lttng_client_callbacks_metadata
#include "lttng-ring-buffer-metadata-client.h"
