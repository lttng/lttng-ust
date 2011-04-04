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
#include <unistd.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>

#include <ust/marker.h>
#include <ust/ustctl.h>
#include "usterr.h"
#include "tp.h"

void inthandler(int sig)
{
	printf("in handler\n");
	exit(0);
}

int init_int_handler(void)
{
	int result;
	struct sigaction act;

	result = sigemptyset(&act.sa_mask);
	if(result == -1) {
		PERROR("sigemptyset");
		return -1;
	}

	act.sa_handler = inthandler;
	act.sa_flags = SA_RESTART;

	/* Only defer ourselves. Also, try to restart interrupted
	 * syscalls to disturb the traced program as little as possible.
	 */
	result = sigaction(SIGINT, &act, NULL);
	if(result == -1) {
		PERROR("sigaction");
		return -1;
	}

	return 0;
}

int main()
{
	int i;

	init_int_handler();

	printf("Hello, World!\n");

	sleep(1);
	for(i=0; i<50; i++) {
		trace_mark(ust, bar, "str %s", "FOOBAZ");
		trace_mark(ust, bar2, "number1 %d number2 %d", 53, 9800);
		trace_hello_tptest(i);
		usleep(100000);
	}

	if (scanf("%*s") == EOF)
		PERROR("scanf failed");

	ustctl_stop_trace(getpid(), "auto");
	ustctl_destroy_trace(getpid(), "auto");

	DBG("TRACE STOPPED");
	if (scanf("%*s") == EOF)
		PERROR("scanf failed");

	return 0;
}
