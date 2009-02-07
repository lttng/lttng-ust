/*
 * Read-Copy Update mechanism for mutual exclusion 
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright IBM Corporation, 2001
 *
 * Author: Dipankar Sarma <dipankar@in.ibm.com>
 * 
 * Based on the original work by Paul McKenney <paulmck@us.ibm.com>
 * and inputs from Rusty Russell, Andrea Arcangeli and Andi Kleen.
 * Papers:
 * http://www.rdrop.com/users/paulmck/paper/rclockpdcsproof.pdf
 * http://lse.sourceforge.net/locking/rclock_OLS.2001.05.01c.sc.pdf (OLS2001)
 *
 * For detailed explanation of Read-Copy Update mechanism see -
 * 		http://lse.sourceforge.net/locking/rcupdate.html
 *
 */

#ifndef __LINUX_RCUPDATE_H
#define __LINUX_RCUPDATE_H

//ust// #include <linux/cache.h>
//ust// #include <linux/spinlock.h>
//ust// #include <linux/threads.h>
//ust// #include <linux/percpu.h>
//ust// #include <linux/cpumask.h>
//ust// #include <linux/seqlock.h>
//ust// #include <linux/lockdep.h>
//ust// #include <linux/completion.h>

/**
 * struct rcu_head - callback structure for use with RCU
 * @next: next update requests in a list
 * @func: actual update function to call after the grace period.
 */
struct rcu_head {
	struct rcu_head *next;
	void (*func)(struct rcu_head *head);
};

//ust// #if defined(CONFIG_CLASSIC_RCU)
//ust// #include <linux/rcuclassic.h>
//ust// #elif defined(CONFIG_TREE_RCU)
//ust// #include <linux/rcutree.h>
//ust// #elif defined(CONFIG_PREEMPT_RCU)
//ust// #include <linux/rcupreempt.h>
//ust// #else
//ust// #error "Unknown RCU implementation specified to kernel configuration"
//ust// #endif /* #else #if defined(CONFIG_CLASSIC_RCU) */
//ust// 
//ust// #define RCU_HEAD_INIT 	{ .next = NULL, .func = NULL }
//ust// #define RCU_HEAD(head) struct rcu_head head = RCU_HEAD_INIT
//ust// #define INIT_RCU_HEAD(ptr) do { \
//ust//        (ptr)->next = NULL; (ptr)->func = NULL; \
//ust// } while (0)
//ust// 
//ust// /**
//ust//  * rcu_read_lock - mark the beginning of an RCU read-side critical section.
//ust//  *
//ust//  * When synchronize_rcu() is invoked on one CPU while other CPUs
//ust//  * are within RCU read-side critical sections, then the
//ust//  * synchronize_rcu() is guaranteed to block until after all the other
//ust//  * CPUs exit their critical sections.  Similarly, if call_rcu() is invoked
//ust//  * on one CPU while other CPUs are within RCU read-side critical
//ust//  * sections, invocation of the corresponding RCU callback is deferred
//ust//  * until after the all the other CPUs exit their critical sections.
//ust//  *
//ust//  * Note, however, that RCU callbacks are permitted to run concurrently
//ust//  * with RCU read-side critical sections.  One way that this can happen
//ust//  * is via the following sequence of events: (1) CPU 0 enters an RCU
//ust//  * read-side critical section, (2) CPU 1 invokes call_rcu() to register
//ust//  * an RCU callback, (3) CPU 0 exits the RCU read-side critical section,
//ust//  * (4) CPU 2 enters a RCU read-side critical section, (5) the RCU
//ust//  * callback is invoked.  This is legal, because the RCU read-side critical
//ust//  * section that was running concurrently with the call_rcu() (and which
//ust//  * therefore might be referencing something that the corresponding RCU
//ust//  * callback would free up) has completed before the corresponding
//ust//  * RCU callback is invoked.
//ust//  *
//ust//  * RCU read-side critical sections may be nested.  Any deferred actions
//ust//  * will be deferred until the outermost RCU read-side critical section
//ust//  * completes.
//ust//  *
//ust//  * It is illegal to block while in an RCU read-side critical section.
//ust//  */
//ust// #define rcu_read_lock() __rcu_read_lock()
//ust// 
//ust// /**
//ust//  * rcu_read_unlock - marks the end of an RCU read-side critical section.
//ust//  *
//ust//  * See rcu_read_lock() for more information.
//ust//  */
//ust// 
//ust// /*
//ust//  * So where is rcu_write_lock()?  It does not exist, as there is no
//ust//  * way for writers to lock out RCU readers.  This is a feature, not
//ust//  * a bug -- this property is what provides RCU's performance benefits.
//ust//  * Of course, writers must coordinate with each other.  The normal
//ust//  * spinlock primitives work well for this, but any other technique may be
//ust//  * used as well.  RCU does not care how the writers keep out of each
//ust//  * others' way, as long as they do so.
//ust//  */
//ust// #define rcu_read_unlock() __rcu_read_unlock()
//ust// 
//ust// /**
//ust//  * rcu_read_lock_bh - mark the beginning of a softirq-only RCU critical section
//ust//  *
//ust//  * This is equivalent of rcu_read_lock(), but to be used when updates
//ust//  * are being done using call_rcu_bh(). Since call_rcu_bh() callbacks
//ust//  * consider completion of a softirq handler to be a quiescent state,
//ust//  * a process in RCU read-side critical section must be protected by
//ust//  * disabling softirqs. Read-side critical sections in interrupt context
//ust//  * can use just rcu_read_lock().
//ust//  *
//ust//  */
//ust// #define rcu_read_lock_bh() __rcu_read_lock_bh()
//ust// 
//ust// /*
//ust//  * rcu_read_unlock_bh - marks the end of a softirq-only RCU critical section
//ust//  *
//ust//  * See rcu_read_lock_bh() for more information.
//ust//  */
//ust// #define rcu_read_unlock_bh() __rcu_read_unlock_bh()
//ust// 
//ust// /**
//ust//  * rcu_read_lock_sched - mark the beginning of a RCU-classic critical section
//ust//  *
//ust//  * Should be used with either
//ust//  * - synchronize_sched()
//ust//  * or
//ust//  * - call_rcu_sched() and rcu_barrier_sched()
//ust//  * on the write-side to insure proper synchronization.
//ust//  */
//ust// #define rcu_read_lock_sched() preempt_disable()
//ust// #define rcu_read_lock_sched_notrace() preempt_disable_notrace()
//ust// 
//ust// /*
//ust//  * rcu_read_unlock_sched - marks the end of a RCU-classic critical section
//ust//  *
//ust//  * See rcu_read_lock_sched for more information.
//ust//  */
//ust// #define rcu_read_unlock_sched() preempt_enable()
//ust// #define rcu_read_unlock_sched_notrace() preempt_enable_notrace()
//ust// 
//ust// 
//ust// 
//ust// /**
//ust//  * rcu_dereference - fetch an RCU-protected pointer in an
//ust//  * RCU read-side critical section.  This pointer may later
//ust//  * be safely dereferenced.
//ust//  *
//ust//  * Inserts memory barriers on architectures that require them
//ust//  * (currently only the Alpha), and, more importantly, documents
//ust//  * exactly which pointers are protected by RCU.
//ust//  */
//ust// 
//ust// #define rcu_dereference(p)     ({ \
//ust// 				typeof(p) _________p1 = ACCESS_ONCE(p); \
//ust// 				smp_read_barrier_depends(); \
//ust// 				(_________p1); \
//ust// 				})
//ust// 
//ust// /**
//ust//  * rcu_assign_pointer - assign (publicize) a pointer to a newly
//ust//  * initialized structure that will be dereferenced by RCU read-side
//ust//  * critical sections.  Returns the value assigned.
//ust//  *
//ust//  * Inserts memory barriers on architectures that require them
//ust//  * (pretty much all of them other than x86), and also prevents
//ust//  * the compiler from reordering the code that initializes the
//ust//  * structure after the pointer assignment.  More importantly, this
//ust//  * call documents which pointers will be dereferenced by RCU read-side
//ust//  * code.
//ust//  */
//ust// 
//ust// #define rcu_assign_pointer(p, v) \
//ust// 	({ \
//ust// 		if (!__builtin_constant_p(v) || \
//ust// 		    ((v) != NULL)) \
//ust// 			smp_wmb(); \
//ust// 		(p) = (v); \
//ust// 	})
//ust// 
//ust// /* Infrastructure to implement the synchronize_() primitives. */
//ust// 
//ust// struct rcu_synchronize {
//ust// 	struct rcu_head head;
//ust// 	struct completion completion;
//ust// };
//ust// 
//ust// extern void wakeme_after_rcu(struct rcu_head  *head);
//ust// 
//ust// /**
//ust//  * synchronize_sched - block until all CPUs have exited any non-preemptive
//ust//  * kernel code sequences.
//ust//  *
//ust//  * This means that all preempt_disable code sequences, including NMI and
//ust//  * hardware-interrupt handlers, in progress on entry will have completed
//ust//  * before this primitive returns.  However, this does not guarantee that
//ust//  * softirq handlers will have completed, since in some kernels, these
//ust//  * handlers can run in process context, and can block.
//ust//  *
//ust//  * This primitive provides the guarantees made by the (now removed)
//ust//  * synchronize_kernel() API.  In contrast, synchronize_rcu() only
//ust//  * guarantees that rcu_read_lock() sections will have completed.
//ust//  * In "classic RCU", these two guarantees happen to be one and
//ust//  * the same, but can differ in realtime RCU implementations.
//ust//  */
//ust// #define synchronize_sched() __synchronize_sched()
//ust// 
//ust// /**
//ust//  * call_rcu - Queue an RCU callback for invocation after a grace period.
//ust//  * @head: structure to be used for queueing the RCU updates.
//ust//  * @func: actual update function to be invoked after the grace period
//ust//  *
//ust//  * The update function will be invoked some time after a full grace
//ust//  * period elapses, in other words after all currently executing RCU
//ust//  * read-side critical sections have completed.  RCU read-side critical
//ust//  * sections are delimited by rcu_read_lock() and rcu_read_unlock(),
//ust//  * and may be nested.
//ust//  */
//ust// extern void call_rcu(struct rcu_head *head,
//ust// 			      void (*func)(struct rcu_head *head));
//ust// 
//ust// /**
//ust//  * call_rcu_bh - Queue an RCU for invocation after a quicker grace period.
//ust//  * @head: structure to be used for queueing the RCU updates.
//ust//  * @func: actual update function to be invoked after the grace period
//ust//  *
//ust//  * The update function will be invoked some time after a full grace
//ust//  * period elapses, in other words after all currently executing RCU
//ust//  * read-side critical sections have completed. call_rcu_bh() assumes
//ust//  * that the read-side critical sections end on completion of a softirq
//ust//  * handler. This means that read-side critical sections in process
//ust//  * context must not be interrupted by softirqs. This interface is to be
//ust//  * used when most of the read-side critical sections are in softirq context.
//ust//  * RCU read-side critical sections are delimited by :
//ust//  *  - rcu_read_lock() and  rcu_read_unlock(), if in interrupt context.
//ust//  *  OR
//ust//  *  - rcu_read_lock_bh() and rcu_read_unlock_bh(), if in process context.
//ust//  *  These may be nested.
//ust//  */
//ust// extern void call_rcu_bh(struct rcu_head *head,
//ust// 			void (*func)(struct rcu_head *head));
//ust// 
//ust// /* Exported common interfaces */
//ust// extern void synchronize_rcu(void);
//ust// extern void rcu_barrier(void);
//ust// extern void rcu_barrier_bh(void);
//ust// extern void rcu_barrier_sched(void);
//ust// 
//ust// /* Internal to kernel */
//ust// extern void rcu_init(void);
//ust// extern int rcu_needs_cpu(int cpu);
//ust// 
#endif /* __LINUX_RCUPDATE_H */
