/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2009 Pierre-Marc Fournier
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>

#define LTTNG_UST_TRACEPOINT_DEFINE
#include "ust_tests_hello_many.h"

int main(int argc, char **argv)
{
	int delay = 0;

	if (argc == 2)
		delay = atoi(argv[1]);

	fprintf(stderr, "Hello, World!\n");

	sleep(delay);

	fprintf(stderr, "Tracing... ");
	lttng_ust_tracepoint(ust_tests_hello_many, tptest_simple1);
	lttng_ust_tracepoint(ust_tests_hello_many, tptest_simple34);
	fprintf(stderr, " done.\n");
	return 0;
}
