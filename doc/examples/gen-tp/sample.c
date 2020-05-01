/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2011-2012 Matthew Khouzam <matthew.khouzam@ericsson.com>
 * Copyright (C) 2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include <unistd.h>

#include "sample_tracepoint.h"
int main(int argc, char **argv)
{
	int i = 0;

	for (i = 0; i < 100000; i++) {
		tracepoint(sample_tracepoint, message,  "Hello World\n");
		usleep(1);
	}
	return 0;
}
