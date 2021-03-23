/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2010 Pierre-Marc Fournier
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _UST_CLOCK_H
#define _UST_CLOCK_H

#include <time.h>
#include <sys/time.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <urcu/system.h>
#include <urcu/arch.h>
#include <lttng/ust-clock.h>

#include "lttng-ust-uuid.h"

struct lttng_ust_trace_clock {
	uint64_t (*read64)(void);
	uint64_t (*freq)(void);
	int (*uuid)(char *uuid);
	const char *(*name)(void);
	const char *(*description)(void);
};

__attribute__((visibility("hidden")))
extern struct lttng_ust_trace_clock *lttng_ust_trace_clock;

void lttng_ust_clock_init(void);

/* Use the kernel MONOTONIC clock. */

static __inline__
uint64_t trace_clock_read64_monotonic(void)
{
	struct timespec ts;

	if (caa_unlikely(clock_gettime(CLOCK_MONOTONIC, &ts))) {
		ts.tv_sec = 0;
		ts.tv_nsec = 0;
	}
	return ((uint64_t) ts.tv_sec * 1000000000ULL) + ts.tv_nsec;
}

static __inline__
uint64_t trace_clock_read64(void)
{
	struct lttng_ust_trace_clock *ltc = CMM_LOAD_SHARED(lttng_ust_trace_clock);

	if (caa_likely(!ltc)) {
		return trace_clock_read64_monotonic();
	} else {
		cmm_read_barrier_depends();	/* load ltc before content */
		return ltc->read64();
	}
}

#endif /* _UST_CLOCK_H */
