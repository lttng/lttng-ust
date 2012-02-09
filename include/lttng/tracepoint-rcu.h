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

#define tp_rcu_read_lock_bp	rcu_read_lock_bp
#define tp_rcu_read_unlock_bp	rcu_read_unlock_bp
#define tp_rcu_dereference_bp	rcu_dereference_bp
#define TP_RCU_LINK_TEST()	1

#else	/* _LGPL_SOURCE */

#define tp_rcu_read_lock_bp	tracepoint_dlopen.rcu_read_lock_sym_bp
#define tp_rcu_read_unlock_bp	tracepoint_dlopen.rcu_read_unlock_sym_bp

#define tp_rcu_dereference_bp(p)					     \
	({								     \
		typeof(p) _________p1 =	URCU_FORCE_CAST(typeof(p),	     \
			tracepoint_dlopen.rcu_dereference_sym_bp(URCU_FORCE_CAST(void *, p))); \
		(_________p1);						     \
	})

#define TP_RCU_LINK_TEST()	tp_rcu_read_lock_bp

#endif	/* _LGPL_SOURCE */

#endif	/* _LTTNG_TRACEPOINT_RCU_H */
