/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _LTTNG_RING_BUFFER_NOHZ_H
#define _LTTNG_RING_BUFFER_NOHZ_H

#include "ust-helper.h"

#ifdef CONFIG_LIB_RING_BUFFER
LTTNG_HIDDEN
void lib_ring_buffer_tick_nohz_flush(void);
LTTNG_HIDDEN
void lib_ring_buffer_tick_nohz_stop(void);
LTTNG_HIDDEN
void lib_ring_buffer_tick_nohz_restart(void);
#else
static inline void lib_ring_buffer_tick_nohz_flush(void)
{
}

static inline void lib_ring_buffer_tick_nohz_stop(void)
{
}

static inline void lib_ring_buffer_tick_nohz_restart(void)
{
}
#endif

#endif /* _LTTNG_RING_BUFFER_NOHZ_H */
