// SPDX-FileCopyrightText: 2009 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
// SPDX-FileCopyrightText: 2009 Paul E. McKenney, IBM Corporation.
//
// SPDX-License-Identifier: LGPL-2.1-or-later

/*
 * Userspace RCU header for LTTng-UST. Derived from liburcu
 * "bulletproof" flavor.
 *
 * Slower RCU read-side adapted for tracing library. Does not require thread
 * registration nor unregistration. Also signal-safe.
 *
 * LGPL-compatible code should include this header with :
 *
 * #define _LGPL_SOURCE
 * #include <lttng/urcu-ust.h>
 */

#ifndef _LTTNG_UST_URCU_H
#define _LTTNG_UST_URCU_H

#include <stdlib.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * See lttng/urcu/pointer.h and lttng/urcu/static/pointer.h for pointer
 * publication headers.
 */
#include <lttng/urcu/pointer.h>

#ifdef _LGPL_SOURCE

#include <lttng/urcu/static/urcu-ust.h>

/*
 * Mappings for static use of the userspace RCU library.
 * Should only be used in LGPL-compatible code.
 */

/*
 * lttng_ust_urcu_read_lock()
 * lttng_ust_urcu_read_unlock()
 *
 * Mark the beginning and end of a read-side critical section.
 */
#define lttng_ust_urcu_read_lock	_lttng_ust_urcu_read_lock
#define lttng_ust_urcu_read_unlock	_lttng_ust_urcu_read_unlock
#define lttng_ust_urcu_read_ongoing	_lttng_ust_urcu_read_ongoing

#else /* !_LGPL_SOURCE */

/*
 * library wrappers to be used by non-LGPL compatible source code.
 * See LGPL-only urcu/static/pointer.h for documentation.
 */

extern void lttng_ust_urcu_read_lock(void);
extern void lttng_ust_urcu_read_unlock(void);
extern int lttng_ust_urcu_read_ongoing(void);

#endif /* !_LGPL_SOURCE */

extern void lttng_ust_urcu_synchronize_rcu(void);

/*
 * lttng_ust_urcu_before_fork, lttng_ust_urcu_after_fork_parent and
 * lttng_ust_urcu_after_fork_child should be called around fork() system
 * calls when the child process is not expected to immediately perform
 * an exec(). For pthread users, see pthread_atfork(3).
 */
extern void lttng_ust_urcu_before_fork(void);
extern void lttng_ust_urcu_after_fork_parent(void);
extern void lttng_ust_urcu_after_fork_child(void);

/*
 * In the UST version, thread registration is performed lazily, but it can be
 * forced by issuing an explicit lttng_ust_urcu_register_thread().
 */
extern void lttng_ust_urcu_register_thread(void);

#ifdef __cplusplus
}
#endif

#endif /* _LTTNG_UST_URCU_H */
