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

/*
 * lttng_ust_getprocname.
 */
#ifdef __linux__

#include <sys/prctl.h>

#define LTTNG_UST_PROCNAME_LEN 17

static inline
void lttng_ust_getprocname(char *name)
{
	(void) prctl(PR_GET_NAME, (unsigned long) name, 0, 0, 0);
}

#elif defined(__FreeBSD__)
#include <stdlib.h>
#include <string.h>

/*
 * Limit imposed by Linux UST-sessiond ABI.
 */
#define LTTNG_UST_PROCNAME_LEN 17

/*
 * Acts like linux prctl, the string is not necessarily 0-terminated if
 * 16-byte long.
 */
static inline
void lttng_ust_getprocname(char *name)
{
	const char *bsd_name;

	bsd_name = getprogname();
	if (!bsd_name)
		name[0] = '\0';
	memcpy(name, bsd_name, LTTNG_UST_PROCNAME_LEN - 1);
}

#endif

#endif /* _UST_COMPAT_H */
