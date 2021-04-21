/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _UST_COMMON_SMP_H
#define _UST_COMMON_SMP_H

/*
 * Returns the total number of CPUs in the system. If the cache is not yet
 * initialized, get the value from the system through sysconf and cache it.
 *
 * If the sysconf call fails, don't populate the cache and return 0.
 */
int num_possible_cpus(void)
	__attribute__((visibility("hidden")));

#define for_each_possible_cpu(cpu)		\
	for ((cpu) = 0; (cpu) < num_possible_cpus(); (cpu)++)

#endif /* _UST_COMMON_SMP_H */
