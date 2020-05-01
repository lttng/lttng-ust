/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright (c) 2009 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (c) 2009 Paul E. McKenney, IBM Corporation.
 *
 * library wrappers to be used by non-LGPL compatible source code.
 */

#include <urcu/uatomic.h>

#include <lttng/urcu/static/pointer.h>
/* Do not #define _LGPL_SOURCE to ensure we can emit the wrapper symbols */
#include <lttng/urcu/pointer.h>

void *lttng_ust_rcu_dereference_sym(void *p)
{
	return _lttng_ust_rcu_dereference(p);
}

void *lttng_ust_rcu_set_pointer_sym(void **p, void *v)
{
	cmm_wmb();
	uatomic_set(p, v);
	return v;
}

void *lttng_ust_rcu_xchg_pointer_sym(void **p, void *v)
{
	cmm_wmb();
	return uatomic_xchg(p, v);
}

void *lttng_ust_rcu_cmpxchg_pointer_sym(void **p, void *old, void *_new)
{
	cmm_wmb();
	return uatomic_cmpxchg(p, old, _new);
}
