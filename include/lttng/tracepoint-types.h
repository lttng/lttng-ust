/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _LTTNG_TRACEPOINT_TYPES_H
#define _LTTNG_TRACEPOINT_TYPES_H

struct lttng_ust_tracepoint_probe {
	void (*func)(void);
	void *data;
};

#define LTTNG_UST_TRACEPOINT_PADDING	16
struct lttng_ust_tracepoint {
	const char *name;
	int state;
	struct lttng_ust_tracepoint_probe *probes;
	int *tracepoint_provider_ref;
	const char *signature;
	char padding[LTTNG_UST_TRACEPOINT_PADDING];
};

#endif /* _LTTNG_TRACEPOINT_TYPES_H */
