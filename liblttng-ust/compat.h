#ifndef _UST_COMPAT_H
#define _UST_COMPAT_H

/*
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <sys/syscall.h>

#ifdef __UCLIBC__
#define __getcpu(cpu, node, cache)	syscall(__NR_getcpu, cpu, node, cache)
static inline
int sched_getcpu(void)
{
	int c, s;

	s = __getcpu(&c, NULL, NULL);
	return (s == -1) ? s : c;
}
#endif	/* __UCLIBC__ */
#endif /* _UST_COMPAT_H */
