/*
 * Copyright (C) 2009  Pierre-Marc Fournier
 * Copyright (C) 2011-2014  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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
		tracef("This is a \"%s\" formatted %d event %lx",
			str, i, l);
	}
	fprintf(stderr, " done.\n");
	return 0;
}
