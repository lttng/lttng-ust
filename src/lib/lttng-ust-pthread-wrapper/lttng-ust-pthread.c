/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright (C) 2013  Mentor Graphics
 */

/*
 * Do _not_ define _LGPL_SOURCE because we don't want to create a
 * circular dependency loop between this malloc wrapper, liburcu and
 * libc.
 */

/* Has to be included first to override dlfcn.h */
#include <common/compat/dlfcn.h>

#include "common/macros.h"
#include <pthread.h>

#define LTTNG_UST_TRACEPOINT_DEFINE
#define LTTNG_UST_TRACEPOINT_CREATE_PROBES
#define LTTNG_UST_TP_IP_PARAM ip
#include "ust_pthread.h"

static __thread int thread_in_trace;

int pthread_mutex_lock(pthread_mutex_t *mutex)
{
	static int (*mutex_lock)(pthread_mutex_t *);
	int retval;

	if (!mutex_lock) {
		mutex_lock = dlsym(RTLD_NEXT, "pthread_mutex_lock");
		if (!mutex_lock) {
			if (thread_in_trace) {
				abort();
			}
			fprintf(stderr, "unable to initialize pthread wrapper library.\n");
			return EINVAL;
		}
	}
	if (thread_in_trace) {
		return mutex_lock(mutex);
	}

	thread_in_trace = 1;
	lttng_ust_tracepoint(lttng_ust_pthread, pthread_mutex_lock_req, mutex,
		LTTNG_UST_CALLER_IP());
	retval = mutex_lock(mutex);
	lttng_ust_tracepoint(lttng_ust_pthread, pthread_mutex_lock_acq, mutex,
		retval, LTTNG_UST_CALLER_IP());
	thread_in_trace = 0;
	return retval;
}

int pthread_mutex_trylock(pthread_mutex_t *mutex)
{
	static int (*mutex_trylock)(pthread_mutex_t *);
	int retval;

	if (!mutex_trylock) {
		mutex_trylock = dlsym(RTLD_NEXT, "pthread_mutex_trylock");
		if (!mutex_trylock) {
			if (thread_in_trace) {
				abort();
			}
			fprintf(stderr, "unable to initialize pthread wrapper library.\n");
			return EINVAL;
		}
	}
	if (thread_in_trace) {
		return mutex_trylock(mutex);
	}

	thread_in_trace = 1;
	retval = mutex_trylock(mutex);
	lttng_ust_tracepoint(lttng_ust_pthread, pthread_mutex_trylock, mutex,
		retval, LTTNG_UST_CALLER_IP());
	thread_in_trace = 0;
	return retval;
}

int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
	static int (*mutex_unlock)(pthread_mutex_t *);
	int retval;

	if (!mutex_unlock) {
		mutex_unlock = dlsym(RTLD_NEXT, "pthread_mutex_unlock");
		if (!mutex_unlock) {
			if (thread_in_trace) {
				abort();
			}
			fprintf(stderr, "unable to initialize pthread wrapper library.\n");
			return EINVAL;
		}
	}
	if (thread_in_trace) {
		return mutex_unlock(mutex);
	}

	thread_in_trace = 1;
	retval = mutex_unlock(mutex);
	lttng_ust_tracepoint(lttng_ust_pthread, pthread_mutex_unlock, mutex,
		retval, LTTNG_UST_CALLER_IP());
	thread_in_trace = 0;
	return retval;
}
