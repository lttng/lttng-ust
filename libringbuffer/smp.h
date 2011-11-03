#ifndef _LIBRINGBUFFER_SMP_H
#define _LIBRINGBUFFER_SMP_H

/*
 * libringbuffer/smp.h
 *
 * Copyright 2011 (c) - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Dual LGPL v2.1/GPL v2 license.
 */

#include <lttng/core.h>

/*
 * 4kB of per-cpu data available. Enough to hold the control structures,
 * but not ring buffers.
 */
#define PER_CPU_MEM_SIZE	4096

extern int __num_possible_cpus;
extern void _get_num_possible_cpus(void);

static inline
int num_possible_cpus(void)
{
	if (!__num_possible_cpus)
		_get_num_possible_cpus();
	return __num_possible_cpus;
}

/*
 * get_cpu() returns the current CPU number. It may change due to
 * migration, so it is only statistically accurate.
 */
#ifndef UST_VALGRIND
static inline
int get_cpu(void)
{
	int cpu;

	cpu = sched_getcpu();
	if (caa_likely(cpu >= 0))
		return cpu;
	/*
	 * If getcpu(2) is not implemented in the Kernel use CPU 0 as fallback.
	 */
	return 0;
}

#else	/* #else #ifndef UST_VALGRIND */
static inline
int get_cpu(void)
{
	/*
	 * Valgrind does not support the sched_getcpu() vsyscall.
	 * It causes it to detect a segfault in the program and stop it.
	 * So if we want to check libust with valgrind, we have to refrain
	 * from using this call. TODO: it would probably be better to return
	 * other values too, to better test it.
	 */
	return 0;
}
#endif	/* #else #ifndef UST_VALGRIND */

static inline
void put_cpu(void)
{
}

#define for_each_possible_cpu(cpu)		\
	for ((cpu) = 0; (cpu) < num_possible_cpus(); (cpu)++)

#endif /* _LIBRINGBUFFER_SMP_H */
