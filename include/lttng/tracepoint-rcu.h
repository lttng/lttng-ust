#ifndef _LTTNG_TRACEPOINT_RCU_H
#define _LTTNG_TRACEPOINT_RCU_H

/*
 * Copyright 2011-2012 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <urcu/compiler.h>

#ifdef _LGPL_SOURCE

#include <urcu-bp.h>

#define tp_rcu_read_lock_bp	rcu_read_lock_bp
#define tp_rcu_read_unlock_bp	rcu_read_unlock_bp
#define tp_rcu_dereference_bp	rcu_dereference
#define TP_RCU_LINK_TEST()	1

#else	/* _LGPL_SOURCE */

#define tp_rcu_read_lock_bp	tracepoint_dlopen_ptr->rcu_read_lock_sym_bp
#define tp_rcu_read_unlock_bp	tracepoint_dlopen_ptr->rcu_read_unlock_sym_bp

#define tp_rcu_dereference_bp(p)					   \
		URCU_FORCE_CAST(__typeof__(p),				   \
			tracepoint_dlopen_ptr->rcu_dereference_sym_bp(URCU_FORCE_CAST(void *, p)))

#define TP_RCU_LINK_TEST()	(tracepoint_dlopen_ptr && tp_rcu_read_lock_bp)

#endif	/* _LGPL_SOURCE */

#endif	/* _LTTNG_TRACEPOINT_RCU_H */
