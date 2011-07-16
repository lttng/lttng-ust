#ifndef _LINUX_RING_BUFFER_API_H
#define _LINUX_RING_BUFFER_API_H

/*
 * linux/ringbuffer/api.h
 *
 * Copyright (C) 2010 - Mathieu Desnoyers "mathieu.desnoyers@efficios.com"
 *
 * Ring Buffer API.
 *
 * Dual LGPL v2.1/GPL v2 license.
 */

#include "backend.h"
#include "frontend.h"
#include <ust/ringbuffer-abi.h>

/*
 * ring_buffer_frontend_api.h contains static inline functions that depend on
 * client static inlines. Hence the inclusion of this "api" header only
 * within the client.
 */
#include "frontend_api.h"

#endif /* _LINUX_RING_BUFFER_API_H */
