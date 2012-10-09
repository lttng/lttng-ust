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
	else
		strncpy(name, bsd_name, LTTNG_UST_PROCNAME_LEN - 1);
}

#endif

#include <errno.h>

#ifndef ENODATA
#define ENODATA	ENOMSG
#endif

#endif /* _UST_COMPAT_H */
