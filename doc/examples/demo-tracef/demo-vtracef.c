/*
 * Copyright (C) 2020  Maxime Roussin-Belanger <maxime.roussinbelanger@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; version 2.1 of
 * the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <lttng/tracef.h>

void print_debug(const char* msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	vtracef(msg, ap);
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
