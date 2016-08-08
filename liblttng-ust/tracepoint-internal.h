#ifndef _LTTNG_TRACEPOINT_INTERNAL_H
#define _LTTNG_TRACEPOINT_INTERNAL_H

/*
 * Copyright (c) 2011 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <urcu/list.h>
#include <urcu-bp.h>
#include <lttng/tracepoint-types.h>

#define TRACE_DEFAULT	TRACE_DEBUG_LINE

struct tracepoint_lib {
	struct cds_list_head list;	/* list of registered libs */
	struct lttng_ust_tracepoint * const *tracepoints_start;
	int tracepoints_count;
	struct cds_list_head callsites;
};

extern int tracepoint_probe_register_noupdate(const char *name,
		void (*callback)(void), void *priv,
		const char *signature);
extern int tracepoint_probe_unregister_noupdate(const char *name,
		void (*callback)(void), void *priv);
extern void tracepoint_probe_update_all(void);
extern int __tracepoint_probe_register_queue_release(const char *name,
		void (*func)(void), void *data, const char *signature);
extern int __tracepoint_probe_unregister_queue_release(const char *name,
		void (*func)(void), void *data);
extern void __tracepoint_probe_prune_release_queue(void);

/*
 * call after disconnection of last probe implemented within a
 * shared object before unmapping the library that contains the probe.
 */
static inline void tracepoint_synchronize_unregister(void)
{
	synchronize_rcu_bp();
}

extern void init_tracepoint(void);
extern void exit_tracepoint(void);

void *lttng_ust_tp_check_weak_hidden1(void);
void *lttng_ust_tp_check_weak_hidden2(void);
void *lttng_ust_tp_check_weak_hidden3(void);

#endif /* _LTTNG_TRACEPOINT_INTERNAL_H */
