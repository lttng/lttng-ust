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

#include <pthread.h>

/*
 * Limit imposed by Linux UST-sessiond ABI.
 */
#define LTTNG_UST_PROCNAME_LEN 17

#define LTTNG_UST_PROCNAME_SUFFIX "-ust"


#if defined(HAVE_PTHREAD_SETNAME_NP_WITH_TID)
static inline
int lttng_pthread_setname_np(const char *name)
{
        return pthread_setname_np(pthread_self(), name);
}

static inline
int lttng_pthread_getname_np(char *name, size_t len)
{
        return pthread_getname_np(pthread_self(), name, len);
}
#elif defined(HAVE_PTHREAD_SETNAME_NP_WITHOUT_TID)
static inline
int lttng_pthread_setname_np(const char *name)
{
        return pthread_setname_np(name);
}

static inline
int lttng_pthread_getname_np(char *name, size_t len)
{
        return pthread_getname_np(name, len);
}
#else
/*
 * For platforms without thread name support, do nothing.
 */
static inline
int lttng_pthread_setname_np(const char *name)
{
        return -ENOSYS;
}

static inline
int lttng_pthread_getname_np(char *name, size_t len)
{
        return -ENOSYS;
}
#endif

static inline
void lttng_ust_getprocname(char *name)
{
	lttng_pthread_getname_np(name, LTTNG_UST_PROCNAME_LEN);
}

static inline
int lttng_ust_setustprocname(void)
{
	int ret = 0, len;
	char name[LTTNG_UST_PROCNAME_LEN];
	int limit = LTTNG_UST_PROCNAME_LEN - strlen(LTTNG_UST_PROCNAME_SUFFIX) - 1;

	lttng_pthread_getname_np(name, LTTNG_UST_PROCNAME_LEN);

	len = strlen(name);
	if (len > limit) {
		len = limit;
	}

	ret = sprintf(name + len, LTTNG_UST_PROCNAME_SUFFIX);
	if (ret != strlen(LTTNG_UST_PROCNAME_SUFFIX)) {
		goto error;
	}

	ret = lttng_pthread_setname_np(name);

error:
	return ret;
}


#include <errno.h>

#ifndef ENODATA
#define ENODATA	ENOMSG
#endif

#endif /* _UST_COMPAT_H */
