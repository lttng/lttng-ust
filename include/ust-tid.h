/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * gettid compatibility layer.
 */

#ifndef _LTTNG_UST_TID_H
#define _LTTNG_UST_TID_H

#ifdef __linux__
#include <sys/syscall.h>
#endif

#if defined(__NR_gettid)

#include <unistd.h>
static inline pid_t lttng_gettid(void)
{
	return syscall(__NR_gettid);
}

#else

#include <sys/types.h>
#include <unistd.h>

/* Fall-back on getpid for tid if not available. */
static inline pid_t lttng_gettid(void)
{
	return getpid();
}

#endif

#endif /* _LTTNG_UST_TID_H */
