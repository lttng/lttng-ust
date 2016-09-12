#ifndef _UST_COMPAT_H
#define _UST_COMPAT_H

/*
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2016 Raphaël Beamonte <raphael.beamonte@gmail.com>
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

/*
 * If pthread_setname_np is available.
 */
#ifdef HAVE_PTHREAD_SETNAME_NP
static inline
int lttng_pthread_setname_np(pthread_t thread, const char *name)
{
	return pthread_setname_np(thread, name);
}
#endif

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

/*
 * If pthread_set_name_np is available.
 */
#ifdef HAVE_PTHREAD_SET_NAME_NP
static inline
int lttng_pthread_setname_np(pthread_t thread, const char *name)
{
	return pthread_set_name_np(thread, name);
}
#endif

#endif

/*
 * If a pthread setname/set_name function is available, declare
 * the setustprocname() function that will add '-ust' to the end
 * of the current process name, while truncating it if needed.
 */
#if defined(HAVE_PTHREAD_SETNAME_NP) || defined(HAVE_PTHREAD_SETNAME_NP)
#define LTTNG_UST_PROCNAME_SUFFIX "-ust"

#include <pthread.h>

static inline
int lttng_ust_setustprocname(void)
{
	int ret = 0, len;
	char name[LTTNG_UST_PROCNAME_LEN];
	int limit = LTTNG_UST_PROCNAME_LEN - strlen(LTTNG_UST_PROCNAME_SUFFIX) - 1;

	lttng_ust_getprocname(name);

	len = strlen(name);
	if (len > limit) {
		len = limit;
	}

	ret = sprintf(name + len, LTTNG_UST_PROCNAME_SUFFIX);
	if (ret != strlen(LTTNG_UST_PROCNAME_SUFFIX)) {
		goto error;
	}

	ret = lttng_pthread_setname_np(pthread_self(), name);

error:
	return ret;
}
#else
static inline
int lttng_ust_setustprocname(void)
{
	return 0;
}
#endif

#include <errno.h>

#ifndef ENODATA
#define ENODATA	ENOMSG
#endif

#endif /* _UST_COMPAT_H */
