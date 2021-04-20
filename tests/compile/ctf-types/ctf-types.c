/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2014 Geneviève Bastien <gbastien@versatic.net>
 */

#include <unistd.h>

#define LTTNG_UST_TRACEPOINT_DEFINE
#include "ust_tests_ctf_types.h"

int main(int argc, char **argv)
{
	int i;
	int delay = 0;

	if (argc == 2)
		delay = atoi(argv[1]);

	fprintf(stderr, "Hello, World!\n");

	sleep(delay);

	fprintf(stderr, "Tracing... ");
	for (i = 0; i < 100; i++) {
		lttng_ust_tracepoint(ust_tests_ctf_types, tptest, i, i % 6,
			i % 21);
	}

	for (i = 0; i < 10; i++) {
		lttng_ust_tracepoint(ust_tests_ctf_types, tptest_bis, i, i % 6);
	}
	fprintf(stderr, " done.\n");
	return 0;
}
