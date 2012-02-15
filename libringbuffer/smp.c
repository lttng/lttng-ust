/*
 * libringbuffer/smp.c
 *
 * Copyright 2011 (c) - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Dual LGPL v2.1/GPL v2 license.
 */

#define _GNU_SOURCE
#include <unistd.h>
#include "usterr.h"
#include <pthread.h>
#include "smp.h"

int __num_possible_cpus;

void _get_num_possible_cpus(void)
{
	int result;

	/* On Linux, when some processors are offline
	 * _SC_NPROCESSORS_CONF counts the offline
	 * processors, whereas _SC_NPROCESSORS_ONLN
	 * does not. If we used _SC_NPROCESSORS_ONLN,
	 * getcpu() could return a value greater than
	 * this sysconf, in which case the arrays
	 * indexed by processor would overflow.
	 */
	result = sysconf(_SC_NPROCESSORS_CONF);
	if (result == -1)
		return;
	__num_possible_cpus = result;
}
