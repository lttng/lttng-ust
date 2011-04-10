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

/* Basic testing program that just records a few events. */

#include <stdio.h>
#include <unistd.h>

#include <ust/marker.h>

int main()
{
	int i;

	printf("Basic test program\n");

	for(i=0; i<50; i++) {
		trace_mark(bar, "str %s", "FOOBAZ");
		trace_mark(bar2, "number1 %d number2 %d", 53, 9800);
		usleep(100000);
	}

	return 0;
}
