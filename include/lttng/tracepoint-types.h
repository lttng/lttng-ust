/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _LTTNG_TRACEPOINT_TYPES_H
#define _LTTNG_TRACEPOINT_TYPES_H

#include <stdint.h>

/*
 * Tracepoint probe definition
 *
 * IMPORTANT: this structure is part of the ABI between instrumented
 * applications and UST. This structure is fixed-size because it is part
 * of a public array of structures. Rather than extending this
 * structure, struct lttng_ust_tracepoint should be extended instead.
 */

struct lttng_ust_tracepoint_probe {
	void (*func)(void);
	void *data;
};

/*
 * Tracepoint definition
 *
 * IMPORTANT: this structure is part of the ABI between instrumented
 * applications and UST. Fields need to be only added at the end, never
 * reordered, never removed.
 *
 * The field @struct_size should be used to determine the size of the
 * structure. It should be queried before using additional fields added
 * at the end of the structure.
 */

struct lttng_ust_tracepoint {
	uint32_t struct_size;

	const char *provider_name;
	const char *event_name;
	int state;
	struct lttng_ust_tracepoint_probe *probes;
	int *tracepoint_provider_ref;
	const char *signature;

	/* End of base ABI. Fields below should be used after checking struct_size. */
};

#endif /* _LTTNG_TRACEPOINT_TYPES_H */
