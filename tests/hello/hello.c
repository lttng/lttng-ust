/*
 * Copyright (C) 2009  Pierre-Marc Fournier
 * Copyright (C) 2011  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>

#include "ust_tests_hello.h"

void inthandler(int sig)
{
	printf("in SIGUSR1 handler\n");
	tracepoint(ust_tests_hello_tptest_sighandler);
}

int init_int_handler(void)
{
	int result;
	struct sigaction act;

	result = sigemptyset(&act.sa_mask);
	if (result == -1) {
		perror("sigemptyset");
		return -1;
	}

	act.sa_handler = inthandler;
	act.sa_flags = SA_RESTART;

	/* Only defer ourselves. Also, try to restart interrupted
	 * syscalls to disturb the traced program as little as possible.
	 */
	result = sigaction(SIGUSR1, &act, NULL);
	if (result == -1) {
		perror("sigaction");
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int i;

	init_int_handler();

	printf("Hello, World!\n");

	sleep(1);

	for (i = 0; i < 50; i++) {
		tracepoint(ust_tests_hello_tptest, i);
		usleep(100000);
	}
	return 0;
}
