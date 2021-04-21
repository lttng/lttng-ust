/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2020 Maxime Roussin-Belanger <maxime.roussinbelanger@gmail.com>
 */

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <lttng/tracef.h>

static
void print_debug(const char* msg, ...)
	__attribute__((format(printf, 1, 2)));
static
void print_debug(const char* msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	lttng_ust_vtracef(msg, ap);
	va_end(ap);
}

int main(int argc, char **argv)
{
	int i;
	int delay = 0;
	const char *str = "mystring test";
	long l = 0x42;

	if (argc > 2)
		delay = atoi(argv[1]);

	fprintf(stderr, "Demo program starting.\n");

	sleep(delay);

	fprintf(stderr, "Tracing... ");

	for (i = 0; i < 5; i++) {
		print_debug("This is a \"%s\" formatted %d event %lx", str, i, l);
	}

	fprintf(stderr, " done.\n");
	return 0;
}
