/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _LTTNG_UST_H
#define _LTTNG_UST_H

#include <signal.h>

#ifdef __cplusplus
extern "C" {
#endif

extern void ust_before_fork(sigset_t *save_sigset);
extern void ust_after_fork_parent(sigset_t *restore_sigset);
extern void ust_after_fork_child(sigset_t *restore_sigset);
extern void ust_after_setns(void);
extern void ust_after_unshare(void);
extern void ust_after_setuid(void);
extern void ust_after_setgid(void);
extern void ust_after_seteuid(void);
extern void ust_after_setegid(void);
extern void ust_after_setreuid(void);
extern void ust_after_setregid(void);
extern void ust_after_setresuid(void);
extern void ust_after_setresgid(void);

#ifdef __cplusplus
}
#endif

#endif /* _LTTNG_UST_H */
