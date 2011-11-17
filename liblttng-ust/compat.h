#ifndef _UST_COMPAT_H
#define _UST_COMPAT_H

/*
 * Copyright (C) 2011   Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * THIS MATERIAL IS PROVIDED AS IS, WITH ABSOLUTELY NO WARRANTY EXPRESSED
 * OR IMPLIED.  ANY USE IS AT YOUR OWN RISK.
 *
 * Permission is hereby granted to use or copy this program
 * for any purpose,  provided the above notices are retained on all copies.
 * Permission to modify the code and to distribute modified code is granted,
 * provided the above notices are retained, and a notice that the code was
 * modified is included with the above copyright notice.
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
