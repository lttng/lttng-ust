/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2021 Michael Jeanson <mjeanson@efficios.com>
 */

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "./libzero.h"
#include "./libone.h"

#define LTTNG_UST_TRACEPOINT_DEFINE
#include "ust_tests_hello.h"

int main(void)
{
	int i, netint;
	long values[] = { 1, 2, 3 };
	char text[10] = "test";
	double dbl = 2.0;
	float flt = 2222.0;
	bool mybool = 123;	/* should print "1" */

	printf("This application is linked on liblttng-ust.\n");

#ifdef USE_LIBZERO
	libzero();
#endif
#ifdef USE_LIBONE
	libone();
#endif

	for (i = 0; i < 10; i++) {
		netint = htonl(i);
		lttng_ust_tracepoint(ust_tests_hello, tptest, i, netint, values,
			   text, strlen(text), dbl, flt, mybool);
	}

	return 0;
}
