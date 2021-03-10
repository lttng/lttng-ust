/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _LTTNG_TRACEPOINT_INTERNAL_H
#define _LTTNG_TRACEPOINT_INTERNAL_H

#include <urcu/list.h>
#include <lttng/tracepoint-types.h>
#include <lttng/ust-events.h>

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

extern void init_tracepoint(void);
extern void exit_tracepoint(void);

void *lttng_ust_tp_check_weak_hidden1(void);
void *lttng_ust_tp_check_weak_hidden2(void);
void *lttng_ust_tp_check_weak_hidden3(void);

#endif /* _LTTNG_TRACEPOINT_INTERNAL_H */
