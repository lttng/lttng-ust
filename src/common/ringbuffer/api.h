/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2010-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Ring Buffer API.
 */

#ifndef _LTTNG_RING_BUFFER_API_H
#define _LTTNG_RING_BUFFER_API_H

#include "backend.h"
#include "frontend.h"

/*
 * ring_buffer_frontend_api.h contains static inline functions that depend on
 * client static inlines. Hence the inclusion of this "api" header only
 * within the client.
 */
#include "frontend_api.h"

#endif /* _LTTNG_RING_BUFFER_API_H */
