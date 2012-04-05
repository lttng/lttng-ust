#ifndef _LTTNG_UST_TID_H
#define _LTTNG_UST_TID_H

/*
 * lttng/ust-tid.h
 *
 * Copyright 2012 (c) - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * gettid compatibility layer.
 *
 * THIS MATERIAL IS PROVIDED AS IS, WITH ABSOLUTELY NO WARRANTY EXPRESSED
 * OR IMPLIED.  ANY USE IS AT YOUR OWN RISK.
 *
 * Permission is hereby granted to use or copy this program
 * for any purpose,  provided the above notices are retained on all copies.
 * Permission to modify the code and to distribute modified code is granted,
 * provided the above notices are retained, and a notice that the code was
 * modified is included with the above copyright notice.
 */

#ifdef __linux__
#include <syscall.h>
#endif

#if defined(_syscall0)
_syscall0(pid_t, gettid)
#elif defined(__NR_gettid)
#include <unistd.h>
static inline pid_t gettid(void)
{
	return syscall(__NR_gettid);
}
#else
#include <sys/types.h>
#include <unistd.h>

/* Fall-back on getpid for tid if not available. */
static inline pid_t gettid(void)
{
	return getpid();
}
#endif

#endif /* _LTTNG_UST_TID_H */
