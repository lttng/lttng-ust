// SPDX-FileCopyrightText: 2021 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
//
// SPDX-License-Identifier: MIT

#ifndef _LTTNG_UST_THREAD_H
#define _LTTNG_UST_THREAD_H

#include <signal.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Initialize this thread's LTTng-UST data structures. There is
 * typically no need to call this, because LTTng-UST initializes its
 * per-thread data structures lazily, but it should be called explicitly
 * upon creation of each thread before signal handlers nesting over
 * those threads use LTTng-UST tracepoints.
 */
void lttng_ust_init_thread(void);

#ifdef __cplusplus
}
#endif

#endif /* _LTTNG_UST_THREAD_H */
