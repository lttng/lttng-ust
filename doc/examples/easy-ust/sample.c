/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2011-2012 Matthew Khouzam <matthew.khouzam@ericsson.com>
 * Copyright (C) 2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include <unistd.h>

/*
 * We need to define LTTNG_UST_TRACEPOINT_DEFINE in one C file in the program
 * before including provider headers.
 */
#define LTTNG_UST_TRACEPOINT_DEFINE
#include "sample_component_provider.h"

int main(void)
{
	int i = 0;

	for (i = 0; i < 100000; i++) {
		lttng_ust_tracepoint(sample_component, message, "Hello World");
		usleep(1);
	}
	return 0;
}
