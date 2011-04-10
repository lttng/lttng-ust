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

#include <stdio.h>
#include <time.h>
#include <errno.h>

#include <ust/marker.h>

int main()
{
	int i;
	struct timespec tv;
	int result;

	tv.tv_sec = 1;
	tv.tv_nsec = 0;

	do {
		result = nanosleep(&tv, &tv);
	} while(result == -1 && errno == EINTR);

	printf("Hello, World!\n");

	for(i=0; i<500; i++) {
		trace_mark(bar, "str %d", i);
		trace_mark(bar2, "number1 %d number2 %d", (int)53, (int)9800);
	}

//	ltt_trace_stop("auto");
//	ltt_trace_destroy("auto");

	return 0;
}
