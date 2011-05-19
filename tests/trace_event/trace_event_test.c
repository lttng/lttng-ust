/*
 * Copyright (C) 2010 Nils Carlson <nils.carlson@ericsson.com>
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
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

#include <stdio.h>
#include <ust/clock.h>

#define TRACEPOINT_CREATE_PROBES
#include "trace_event_test.h"

int main(int argc, char * argv[])
{
	unsigned long time, i;

	for (i = 0; i < 10; i++) {
		time = trace_clock_read64();
		tracepoint(test, time, i);
	}
	return 0;
}
