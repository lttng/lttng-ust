/* Copyright (C) 2009  Pierre-Marc Fournier
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

/* This test generates a trace of a certain number of events. It is used to
 * check that no events are lost while tracing.
 */

#include <string.h>
#include <stdlib.h>
#include <ust/ust.h>

#define N_ITER 100000

int main()
{
	int i;

	for(i=0; i<N_ITER; i++) {
		trace_mark(an_event, "%d", i);
		trace_mark(another_event, "%s", "Hello, World!");
	}

	return 0;
}
