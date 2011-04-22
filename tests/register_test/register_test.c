/* Copyright (C) 2010 Nils Carlson
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
#include <pthread.h>

#include <ust/marker.h>
#include "usterr.h"
#include "tp.h"

DEFINE_TRACEPOINT(hello_tptest);


struct hello_trace_struct {
	char *message;
};

struct hello_trace_struct hello_struct = {
	.message = "ehlo\n",
};

void tptest_probe(void *data, int anint)
{
	struct hello_trace_struct *hello;
	char message[30];
	hello=(struct hello_trace_struct *)data;
	//printf("this is the message: %s\n", hello->message);
	snprintf(message, 30, "this is the %s\n", hello->message);
}


#define HELLO_LENGTH 100

static void * register_thread_main(void *data)
{
	int i, j = 0;

	struct hello_trace_struct hello[HELLO_LENGTH];

	for (i=0; i<HELLO_LENGTH; i++) {
		hello[i].message = malloc(6*sizeof(char));
		hello[i].message[0] = 'a'+i%25;
		memcpy(&hello[i].message[1], "ello", 5);
	}

	for (i=0; i<1000; i++) {
		while (!register_tracepoint(hello_tptest, tptest_probe,
						    &hello[j%HELLO_LENGTH])) {
			usleep(10);
			j++;
		}
		printf("Registered all\n");
		while (!unregister_tracepoint(hello_tptest, tptest_probe,
						      &hello[j%HELLO_LENGTH])) {
			usleep(10);
			j++;
		}
		printf("Unregistered all\n");
	}
	return NULL;
}


int main(int argc, char **argv)
{
	pthread_t register_thread;
	int i;

	pthread_create(&register_thread, NULL, register_thread_main, NULL);
	for(i=0; i<1000000; i++) {
		tracepoint(hello_tptest, i);
	}

	return 0;
}
