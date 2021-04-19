/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _LTTNG_TRACEPOINT_RCU_H
#define _LTTNG_TRACEPOINT_RCU_H

#include <urcu/compiler.h>
#include <lttng/urcu/pointer.h>

#ifdef _LGPL_SOURCE

#include <lttng/urcu/urcu-ust.h>

#define tp_rcu_read_lock	lttng_ust_urcu_read_lock
#define tp_rcu_read_unlock	lttng_ust_urcu_read_unlock
#define tp_rcu_dereference	lttng_ust_rcu_dereference
#define TP_RCU_LINK_TEST()	1

#else	/* _LGPL_SOURCE */

#define tp_rcu_read_lock	lttng_ust_tracepoint_dlopen_ptr->rcu_read_lock_sym
#define tp_rcu_read_unlock	lttng_ust_tracepoint_dlopen_ptr->rcu_read_unlock_sym

#define tp_rcu_dereference(p)						   \
		URCU_FORCE_CAST(__typeof__(p),				   \
			lttng_ust_tracepoint_dlopen_ptr->rcu_dereference_sym(URCU_FORCE_CAST(void *, p)))

#define TP_RCU_LINK_TEST()	(lttng_ust_tracepoint_dlopen_ptr && tp_rcu_read_lock)

#endif	/* _LGPL_SOURCE */

#endif	/* _LTTNG_TRACEPOINT_RCU_H */
