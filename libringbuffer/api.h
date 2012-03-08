#ifndef _LTTNG_RING_BUFFER_API_H
#define _LTTNG_RING_BUFFER_API_H

/*
 * libringbuffer/api.h
 *
 * Ring Buffer API.
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

#include "backend.h"
#include "frontend.h"
#include <lttng/ringbuffer-abi.h>

/*
 * ring_buffer_frontend_api.h contains static inline functions that depend on
 * client static inlines. Hence the inclusion of this "api" header only
 * within the client.
 */
#include "frontend_api.h"

#endif /* _LTTNG_RING_BUFFER_API_H */
