/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _LTTNG_TRACEPOINT_RCU_H
#define _LTTNG_TRACEPOINT_RCU_H

#include <urcu/compiler.h>
#include <lttng/urcu/pointer.h>
#include <lttng/ust-api-compat.h>

#ifdef _LGPL_SOURCE

#include <lttng/urcu/urcu-ust.h>

#define lttng_ust_tp_rcu_read_lock	lttng_ust_urcu_read_lock
#define lttng_ust_tp_rcu_read_unlock	lttng_ust_urcu_read_unlock
#define lttng_ust_tp_rcu_dereference	lttng_ust_rcu_dereference
#define LTTNG_UST_TP_RCU_LINK_TEST()	1

#else	/* _LGPL_SOURCE */

#define lttng_ust_tp_rcu_read_lock	lttng_ust_tracepoint_dlopen_ptr->rcu_read_lock_sym
#define lttng_ust_tp_rcu_read_unlock	lttng_ust_tracepoint_dlopen_ptr->rcu_read_unlock_sym

#define lttng_ust_tp_rcu_dereference(p)						   \
		URCU_FORCE_CAST(__typeof__(p),				   \
			lttng_ust_tracepoint_dlopen_ptr->rcu_dereference_sym(URCU_FORCE_CAST(void *, p)))

#define LTTNG_UST_TP_RCU_LINK_TEST()	(lttng_ust_tracepoint_dlopen_ptr && tp_rcu_read_lock)

#endif	/* _LGPL_SOURCE */

#if LTTNG_UST_COMPAT_API(0)
#define tp_rcu_read_lock	lttng_ust_tp_rcu_read_lock
#define tp_rcu_read_unlock	lttng_ust_tp_rcu_read_unlock
#define tp_rcu_dereference	lttng_ust_tp_rcu_dereference
#define TP_RCU_LINK_TEST	LTTNG_UST_TP_RCU_LINK_TEST
#endif

#endif	/* _LTTNG_TRACEPOINT_RCU_H */
