/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _UST_COMMON_TRACEPOINT_H
#define _UST_COMMON_TRACEPOINT_H

#define LTTNG_UST_TRACEPOINT_LOGLEVEL_DEFAULT	LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_LINE

/*
 * These symbols are ABI between liblttng-ust-tracepoint and liblttng-ust,
 * which is why they are not hidden and not part of the public API.
 */
int lttng_ust_tp_probe_register_queue_release(const char *provider_name, const char *event_name,
		void (*func)(void), void *data, const char *signature);
int lttng_ust_tp_probe_unregister_queue_release(const char *provider_name, const char *event_name,
		void (*func)(void), void *data);
void lttng_ust_tp_probe_prune_release_queue(void);

void lttng_ust_tp_init(void);
void lttng_ust_tp_exit(void);


#endif /* _UST_COMMON_TRACEPOINT_H */
