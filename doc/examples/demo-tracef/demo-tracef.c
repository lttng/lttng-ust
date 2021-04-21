/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2009 Pierre-Marc Fournier
 * Copyright (C) 2011-2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <lttng/tracef.h>

int main(int argc, char **argv)
{
	int i;
	int delay = 0;
	const char *str = "mystring test";
	long l = 0x42;

	if (argc == 2)
		delay = atoi(argv[1]);

	fprintf(stderr, "Demo program starting.\n");

	sleep(delay);

	fprintf(stderr, "Tracing... ");
	for (i = 0; i < 5; i++) {
		lttng_ust_tracef("This is a \"%s\" formatted %d event %lx",
			str, i, l);
	}
	fprintf(stderr, " done.\n");
	return 0;
}
