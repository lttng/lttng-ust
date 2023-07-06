// SPDX-FileCopyrightText: 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
//
// SPDX-License-Identifier: MIT

#ifndef _LTTNG_UST_FORK_H
#define _LTTNG_UST_FORK_H

#include <signal.h>

#ifdef __cplusplus
extern "C" {
#endif

void lttng_ust_before_fork(sigset_t *save_sigset);
void lttng_ust_after_fork_parent(sigset_t *restore_sigset);
void lttng_ust_after_fork_child(sigset_t *restore_sigset);
void lttng_ust_after_setns(void);
void lttng_ust_after_unshare(void);
void lttng_ust_after_setuid(void);
void lttng_ust_after_setgid(void);
void lttng_ust_after_seteuid(void);
void lttng_ust_after_setegid(void);
void lttng_ust_after_setreuid(void);
void lttng_ust_after_setregid(void);
void lttng_ust_after_setresuid(void);
void lttng_ust_after_setresgid(void);

#ifdef __cplusplus
}
#endif

#endif /* _LTTNG_UST_FORK_H */
