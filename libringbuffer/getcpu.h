#ifndef _LTTNG_GETCPU_H
#define _LTTNG_GETCPU_H

/*
 * Copyright (c) 2011 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <urcu/compiler.h>
#include <sched.h>

#ifdef UST_VALGRIND

/*
 * Fallback on cpu 0 if liblttng-ust is build with Valgrind support.
 * get_cpu() returns the current CPU number. It may change due to
 * migration, so it is only statistically accurate.
 */
static inline
int lttng_ust_get_cpu(void)
{
	return 0;
}

#else

/*
 * If getcpu is not implemented in the kernel, use cpu 0 as fallback.
 */
static inline
int lttng_ust_get_cpu(void)
{
	int cpu;

	cpu = sched_getcpu();
	if (caa_unlikely(cpu < 0))
		return 0;
	return cpu;
}

#endif

#endif /* _LTTNG_GETCPU_H */
