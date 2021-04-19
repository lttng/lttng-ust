/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * gettid compatibility layer.
 */

#ifndef _UST_COMMON_COMPAT_GETTID_H
#define _UST_COMMON_COMPAT_GETTID_H

#ifdef __linux__
#include <sys/syscall.h>
#endif

#ifdef HAVE_GETTID

#include <unistd.h>
static inline pid_t lttng_gettid(void)
{
	return gettid();
}

#elif defined(__NR_gettid)

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

#endif /* _UST_COMMON_COMPAT_GETTID_H */
