/*
 * Copyright (C) 2010 David Goulet <david.goulet@polymtl.ca>
 * Copyright (C) 2010 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

/*
 * This test is aimed at testing tracepoint *with* ust_marker :
 *
 * 1) tracepoint named : "ust_event"
 * 	-) Probe 1 registered and recording the value 42
 */

#include <stdio.h>

#define TRACEPOINT_CREATE_PROBES
#include "tracepoint_benchmark.h"

/* Yes, this is now internal. */
#include "../../../libust/type-serializer.h"

#define NR_EVENTS	10000000

void tp_probe(void *data, unsigned int p1);

DEFINE_UST_MARKER_TP(event, ust_event, tp_probe, "p1 %u");

/*
 * Probe 1 --> ust_event
 */
void tp_probe(void *data, unsigned int p1)
{
	struct ust_marker *marker;

	marker = &GET_UST_MARKER(event);
	ltt_specialized_trace(marker, data, &p1, sizeof(p1), sizeof(p1));
}

static void __attribute__((constructor)) init()
{
	__register_tracepoint(ust_event, tp_probe, NULL);
}

void single_trace(unsigned int v)
{
	tracepoint(ust_event, v);
}

void do_trace(void)
{
	long i;

	for (i = 0; i < NR_EVENTS; i++)
		single_trace(42);
}

void *thr1(void *arg)
{
	do_trace();
	return ((void*)1);
}

int main(int argc, char **argv)
{
	int err, i;
	void *tret;
	pthread_t *tid;
	int nr_threads;

	if (argc > 1)
		nr_threads = atoi(argv[1]);
	else
		nr_threads = 1;
	printf("Starting test for %d threads\n", nr_threads);

	tid = malloc(sizeof(*tid) * nr_threads);

	for (i = 0; i < nr_threads; i++) {
		err = pthread_create(&tid[i], NULL, thr1, NULL);
		if (err != 0)
			exit(1);
	}

	for (i = 0; i < nr_threads; i++) {
		err = pthread_join(tid[i], &tret);
		if (err != 0)
			exit(1);
	}
	free(tid);
	return 0;
}
