/*
 * libringbuffer/smp.c
 *
 * Copyright (C) 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; only
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#define _GNU_SOURCE
#define _LGPL_SOURCE
#include <unistd.h>
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
