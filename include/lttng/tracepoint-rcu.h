#ifndef _LTTNG_TRACEPOINT_RCU_H
#define _LTTNG_TRACEPOINT_RCU_H

/*
 * Copyright (c) 2011 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * THIS MATERIAL IS PROVIDED AS IS, WITH ABSOLUTELY NO WARRANTY EXPRESSED
 * OR IMPLIED.  ANY USE IS AT YOUR OWN RISK.
 *
 * Permission is hereby granted to use or copy this program
 * for any purpose,  provided the above notices are retained on all copies.
 * Permission to modify the code and to distribute modified code is granted,
 * provided the above notices are retained, and a notice that the code was
 * modified is included with the above copyright notice.
 *
 * This file allows weak linking on tracepoint RCU symbols for non-LGPL
 * code.
 */

#include <urcu/compiler.h>

#ifdef _LGPL_SOURCE

#include <urcu-bp.h>

#define TP_RCU_LINK_TEST()	1
#define tp_rcu_read_lock_bp	rcu_read_lock_bp
#define tp_rcu_read_unlock_bp	rcu_read_unlock_bp
#define tp_rcu_dereference_bp	rcu_dereference_bp

#else	/* _LGPL_SOURCE */

#define TP_RCU_LINK_TEST()     tp_rcu_read_lock_bp

/* Symbols looked up with dlsym */
static void (*tp_rcu_read_lock_bp)(void) __attribute__((unused));
static void (*tp_rcu_read_unlock_bp)(void) __attribute__((unused));
static void *(*tp_rcu_dereference_sym_bp)(void *p) __attribute__((unused));

#define tp_rcu_dereference_bp(p)					     \
	({								     \
		typeof(p) _________p1 =	URCU_FORCE_CAST(typeof(p),	     \
			tp_rcu_dereference_sym_bp(URCU_FORCE_CAST(void *, p))); \
		(_________p1);						     \
	})

#endif	/* _LGPL_SOURCE */

#endif	/* _LTTNG_TRACEPOINT_RCU_H */
