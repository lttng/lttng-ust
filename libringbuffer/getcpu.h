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
#include <urcu/system.h>
#include <urcu/arch.h>
#include <config.h>

void lttng_ust_getcpu_init(void);

extern int (*lttng_get_cpu)(void);

#ifdef LTTNG_UST_DEBUG_VALGRIND

/*
 * Fallback on cpu 0 if liblttng-ust is build with Valgrind support.
 * get_cpu() returns the current CPU number. It may change due to
 * migration, so it is only statistically accurate.
 */
static inline
int lttng_ust_get_cpu_internal(void)
{
	return 0;
}

#else

/*
 * sched_getcpu.
 */
#ifdef __linux__

#if !HAVE_SCHED_GETCPU
#include <sys/syscall.h>
#define __getcpu(cpu, node, cache)	syscall(__NR_getcpu, cpu, node, cache)
/*
 * If getcpu is not implemented in the kernel, use cpu 0 as fallback.
 */
static inline
int lttng_ust_get_cpu_internal(void)
{
	int cpu, ret;

	ret = __getcpu(&cpu, NULL, NULL);
	if (caa_unlikely(ret < 0))
		return 0;
	return cpu;
}
#else /* HAVE_SCHED_GETCPU */
#include <sched.h>

/*
 * If getcpu is not implemented in the kernel, use cpu 0 as fallback.
 */
static inline
int lttng_ust_get_cpu_internal(void)
{
	int cpu;

	cpu = sched_getcpu();
	if (caa_unlikely(cpu < 0))
		return 0;
	return cpu;
}
#endif	/* HAVE_SCHED_GETCPU */

#elif (defined(__FreeBSD__) || defined(__CYGWIN__))

/*
 * FreeBSD and Cygwin do not allow query of CPU ID. Always use CPU
 * number 0, with the assocated performance degradation on SMP.
 */
static inline
int lttng_ust_get_cpu_internal(void)
{
	return 0;
}

#else
#error "Please add support for your OS into liblttng-ust/compat.h."
#endif

#endif

static inline
int lttng_ust_get_cpu(void)
{
	int (*getcpu)(void) = CMM_LOAD_SHARED(lttng_get_cpu);

	if (caa_likely(!getcpu)) {
		return lttng_ust_get_cpu_internal();
	} else {
		return getcpu();
	}
}

#endif /* _LTTNG_GETCPU_H */
