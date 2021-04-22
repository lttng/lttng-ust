/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2010 Pierre-Marc Fournier
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _LTTNG_UST_COMMON_CLOCK_H
#define _LTTNG_UST_COMMON_CLOCK_H

#include "common/clock.h"

void lttng_ust_clock_init(void)
	__attribute__((visibility("hidden")));

#endif /* _LTTNG_UST_COMMON_CLOCK_H */
