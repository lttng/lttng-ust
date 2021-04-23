/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2012-2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _LTTNG_UST_RINGBUFFER_RB_INIT_H
#define _LTTNG_UST_RINGBUFFER_RB_INIT_H

void lttng_ringbuffer_alloc_tls(void)
	__attribute__((visibility("hidden")));

void lttng_ust_ringbuffer_set_allow_blocking(void)
	__attribute__((visibility("hidden")));

#endif /* _LTTNG_UST_RINGBUFFER_RB_INIT_H */
