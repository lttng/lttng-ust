// SPDX-FileCopyrightText: 2009 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
// SPDX-FileCopyrightText: 2009 Paul E. McKenney, IBM Corporation.
//
// SPDX-License-Identifier: LGPL-2.1-or-later

/*
 * Userspace RCU header.
 *
 * TO BE INCLUDED ONLY IN CODE THAT IS TO BE RECOMPILED ON EACH LIBURCU
 * RELEASE. See urcu.h for linking dynamically with the userspace rcu library.
 */

#ifndef _LTTNG_UST_URCU_STATIC_H
#define _LTTNG_UST_URCU_STATIC_H

#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

#include <urcu/config.h>
#include <urcu/compiler.h>
#include <urcu/arch.h>
#include <urcu/system.h>
#include <urcu/uatomic.h>
#include <urcu/list.h>
#include <urcu/tls-compat.h>
#include <urcu/debug.h>

/*
 * This code section can only be included in LGPL 2.1 compatible source code.
 * See below for the function call wrappers which can be used in code meant to
 * be only linked with the Userspace RCU library. This comes with a small
 * performance degradation on the read-side due to the added function calls.
 * This is required to permit relinking with newer versions of the library.
 */

#ifdef __cplusplus
extern "C" {
#endif

enum lttng_ust_urcu_state {
	LTTNG_UST_URCU_READER_ACTIVE_CURRENT,
	LTTNG_UST_URCU_READER_ACTIVE_OLD,
	LTTNG_UST_URCU_READER_INACTIVE,
};

/*
 * The trick here is that LTTNG_UST_URCU_GP_CTR_PHASE must be a multiple of 8 so we can use a
 * full 8-bits, 16-bits or 32-bits bitmask for the lower order bits.
 */
#define LTTNG_UST_URCU_GP_COUNT		(1UL << 0)
/* Use the amount of bits equal to half of the architecture long size */
#define LTTNG_UST_URCU_GP_CTR_PHASE		(1UL << (sizeof(long) << 2))
#define LTTNG_UST_URCU_GP_CTR_NEST_MASK	(LTTNG_UST_URCU_GP_CTR_PHASE - 1)

/*
 * Used internally by _lttng_ust_urcu_read_lock.
 */
extern void lttng_ust_urcu_register(void);

struct lttng_ust_urcu_gp {
	/*
	 * Global grace period counter.
	 * Contains the current LTTNG_UST_URCU_GP_CTR_PHASE.
	 * Also has a LTTNG_UST_URCU_GP_COUNT of 1, to accelerate the reader fast path.
	 * Written to only by writer with mutex taken.
	 * Read by both writer and readers.
	 */
	unsigned long ctr;
} __attribute__((aligned(CAA_CACHE_LINE_SIZE)));

extern struct lttng_ust_urcu_gp lttng_ust_urcu_gp;

struct lttng_ust_urcu_reader {
	/* Data used by both reader and lttng_ust_urcu_synchronize_rcu() */
	unsigned long ctr;
	/* Data used for registry */
	struct cds_list_head node __attribute__((aligned(CAA_CACHE_LINE_SIZE)));
	pthread_t tid;
	int alloc;	/* registry entry allocated */
};

/*
 * Bulletproof version keeps a pointer to a registry not part of the TLS.
 * Adds a pointer dereference on the read-side, but won't require to unregister
 * the reader thread.
 */
extern DECLARE_URCU_TLS(struct lttng_ust_urcu_reader *, lttng_ust_urcu_reader);

#ifdef CONFIG_RCU_FORCE_SYS_MEMBARRIER
#define lttng_ust_urcu_has_sys_membarrier	1
#else
extern int lttng_ust_urcu_has_sys_membarrier;
#endif

static inline void lttng_ust_urcu_smp_mb_slave(void)
{
	if (caa_likely(lttng_ust_urcu_has_sys_membarrier))
		cmm_barrier();
	else
		cmm_smp_mb();
}

static inline enum lttng_ust_urcu_state lttng_ust_urcu_reader_state(unsigned long *ctr)
{
	unsigned long v;

	if (ctr == NULL)
		return LTTNG_UST_URCU_READER_INACTIVE;
	/*
	 * Make sure both tests below are done on the same version of *value
	 * to insure consistency.
	 */
	v = CMM_LOAD_SHARED(*ctr);
	if (!(v & LTTNG_UST_URCU_GP_CTR_NEST_MASK))
		return LTTNG_UST_URCU_READER_INACTIVE;
	if (!((v ^ lttng_ust_urcu_gp.ctr) & LTTNG_UST_URCU_GP_CTR_PHASE))
		return LTTNG_UST_URCU_READER_ACTIVE_CURRENT;
	return LTTNG_UST_URCU_READER_ACTIVE_OLD;
}

/*
 * Helper for _lttng_ust_urcu_read_lock().  The format of lttng_ust_urcu_gp.ctr (as well as
 * the per-thread rcu_reader.ctr) has the upper bits containing a count of
 * _lttng_ust_urcu_read_lock() nesting, and a lower-order bit that contains either zero
 * or LTTNG_UST_URCU_GP_CTR_PHASE.  The smp_mb_slave() ensures that the accesses in
 * _lttng_ust_urcu_read_lock() happen before the subsequent read-side critical section.
 */
static inline void _lttng_ust_urcu_read_lock_update(unsigned long tmp)
{
	if (caa_likely(!(tmp & LTTNG_UST_URCU_GP_CTR_NEST_MASK))) {
		_CMM_STORE_SHARED(URCU_TLS(lttng_ust_urcu_reader)->ctr, _CMM_LOAD_SHARED(lttng_ust_urcu_gp.ctr));
		lttng_ust_urcu_smp_mb_slave();
	} else
		_CMM_STORE_SHARED(URCU_TLS(lttng_ust_urcu_reader)->ctr, tmp + LTTNG_UST_URCU_GP_COUNT);
}

/*
 * Enter an RCU read-side critical section.
 *
 * The first cmm_barrier() call ensures that the compiler does not reorder
 * the body of _lttng_ust_urcu_read_lock() with a mutex.
 *
 * This function and its helper are both less than 10 lines long.  The
 * intent is that this function meets the 10-line criterion in LGPL,
 * allowing this function to be invoked directly from non-LGPL code.
 */
static inline void _lttng_ust_urcu_read_lock(void)
{
	unsigned long tmp;

	if (caa_unlikely(!URCU_TLS(lttng_ust_urcu_reader)))
		lttng_ust_urcu_register(); /* If not yet registered. */
	cmm_barrier();	/* Ensure the compiler does not reorder us with mutex */
	tmp = URCU_TLS(lttng_ust_urcu_reader)->ctr;
	urcu_assert((tmp & LTTNG_UST_URCU_GP_CTR_NEST_MASK) != LTTNG_UST_URCU_GP_CTR_NEST_MASK);
	_lttng_ust_urcu_read_lock_update(tmp);
}

/*
 * Exit an RCU read-side critical section.  This function is less than
 * 10 lines of code, and is intended to be usable by non-LGPL code, as
 * called out in LGPL.
 */
static inline void _lttng_ust_urcu_read_unlock(void)
{
	unsigned long tmp;

	tmp = URCU_TLS(lttng_ust_urcu_reader)->ctr;
	urcu_assert(tmp & LTTNG_UST_URCU_GP_CTR_NEST_MASK);
	/* Finish using rcu before decrementing the pointer. */
	lttng_ust_urcu_smp_mb_slave();
	_CMM_STORE_SHARED(URCU_TLS(lttng_ust_urcu_reader)->ctr, tmp - LTTNG_UST_URCU_GP_COUNT);
	cmm_barrier();	/* Ensure the compiler does not reorder us with mutex */
}

/*
 * Returns whether within a RCU read-side critical section.
 *
 * This function is less than 10 lines long.  The intent is that this
 * function meets the 10-line criterion for LGPL, allowing this function
 * to be invoked directly from non-LGPL code.
 */
static inline int _lttng_ust_urcu_read_ongoing(void)
{
	if (caa_unlikely(!URCU_TLS(lttng_ust_urcu_reader)))
		lttng_ust_urcu_register(); /* If not yet registered. */
	return URCU_TLS(lttng_ust_urcu_reader)->ctr & LTTNG_UST_URCU_GP_CTR_NEST_MASK;
}

#ifdef __cplusplus
}
#endif

#endif /* _LTTNG_UST_URCU_STATIC_H */
