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

struct tracepoint_lib {
	struct cds_list_head list;	/* list of registered libs */
	struct lttng_ust_tracepoint * const *tracepoints_start;
	int tracepoints_count;
	struct cds_list_head callsites;
};

int tracepoint_probe_register_noupdate(const char *provider_name, const char *event_name,
		void (*callback)(void), void *priv,
		const char *signature)
	__attribute__((visibility("hidden")));

int tracepoint_probe_unregister_noupdate(const char *provider_name, const char *event_name,
		void (*callback)(void), void *priv)
	__attribute__((visibility("hidden")));

void tracepoint_probe_update_all(void)
	__attribute__((visibility("hidden")));


void *lttng_ust_tp_check_weak_hidden1(void)
	__attribute__((visibility("hidden")));

void *lttng_ust_tp_check_weak_hidden2(void)
	__attribute__((visibility("hidden")));

void *lttng_ust_tp_check_weak_hidden3(void)
	__attribute__((visibility("hidden")));

#endif /* _LTTNG_TRACEPOINT_INTERNAL_H */
