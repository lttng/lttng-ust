/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2012-2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _LTTNG_UST_LIB_RINGBUFFER_RB_INIT_H
#define _LTTNG_UST_LIB_RINGBUFFER_RB_INIT_H

#include "ust-helper.h"

LTTNG_HIDDEN
void lttng_fixup_ringbuffer_tls(void);
LTTNG_HIDDEN
void lttng_ust_ringbuffer_set_allow_blocking(void);

#endif /* _LTTNG_UST_LIB_RINGBUFFER_RB_INIT_H */
