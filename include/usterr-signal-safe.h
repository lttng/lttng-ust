/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2009 Pierre-Marc Fournier
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _USTERR_SIGNAL_SAFE_H
#define _USTERR_SIGNAL_SAFE_H

#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <ust-share.h>
#include "ust-tid.h"
#include "ust-snprintf.h"

enum ust_loglevel {
	UST_LOGLEVEL_UNKNOWN = 0,
	UST_LOGLEVEL_NORMAL,
	UST_LOGLEVEL_DEBUG,
};

extern volatile enum ust_loglevel ust_loglevel;
void init_usterr(void);

#ifdef LTTNG_UST_DEBUG
static inline int ust_debug(void)
{
	return 1;
}
#else /* #ifdef LTTNG_UST_DEBUG */
static inline int ust_debug(void)
{
	return ust_loglevel == UST_LOGLEVEL_DEBUG;
}
#endif /* #else #ifdef LTTNG_UST_DEBUG */

#ifndef UST_COMPONENT
//#error UST_COMPONENT is undefined
#define UST_COMPONENT libust
#endif

/* To stringify the expansion of a define */
#define UST_XSTR(d) UST_STR(d)
#define UST_STR(s) #s

#define USTERR_MAX_LEN	512

/* We sometimes print in the tracing path, and tracing can occur in
 * signal handlers, so we must use a print method which is signal safe.
 */
/* Can't use dynamic allocation. Limit ourselves to USTERR_MAX_LEN chars. */
/* Add end of string in case of buffer overflow. */
#define sigsafe_print_err(fmt, args...)					\
do {									\
	if (ust_debug()) {						\
		char ____buf[USTERR_MAX_LEN];				\
		int ____saved_errno;					\
									\
		____saved_errno = errno;	/* signal-safety */	\
		ust_safe_snprintf(____buf, sizeof(____buf), fmt, ## args); \
		____buf[sizeof(____buf) - 1] = 0;			\
		ust_patient_write(STDERR_FILENO, ____buf, strlen(____buf)); \
		errno = ____saved_errno;	/* signal-safety */	\
		fflush(stderr);						\
	}								\
} while (0)

#define UST_STR_COMPONENT UST_XSTR(UST_COMPONENT)

#define ERRMSG(fmt, args...)			\
	do {					\
		sigsafe_print_err(UST_STR_COMPONENT "[%ld/%ld]: " fmt " (in %s() at " __FILE__ ":" UST_XSTR(__LINE__) ")\n", \
		(long) getpid(),		\
		(long) lttng_gettid(),		\
		## args, __func__);		\
	} while(0)


#define DBG(fmt, args...)	ERRMSG(fmt, ## args)
#define DBG_raw(fmt, args...)	sigsafe_print_err(fmt, ## args)
#define WARN(fmt, args...)	ERRMSG("Warning: " fmt, ## args)
#define ERR(fmt, args...)	ERRMSG("Error: " fmt, ## args)
#define BUG(fmt, args...)	ERRMSG("BUG: " fmt, ## args)

#if !defined(__GLIBC__) || ((_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && !defined(_GNU_SOURCE))
/*
 * Version using XSI strerror_r.
 */
#define PERROR(call, args...)						\
	do {								\
		if (ust_debug()) {					\
			char buf[200] = "Error in strerror_r()";	\
			strerror_r(errno, buf, sizeof(buf));		\
			ERRMSG("Error: " call ": %s", ## args, buf);	\
		}							\
	} while(0)
#else
/*
 * Version using GNU strerror_r, for linux with appropriate defines.
 */
#define PERROR(call, args...)						\
	do {								\
		if (ust_debug()) {					\
			char *buf;					\
			char tmp[200];					\
			buf = strerror_r(errno, tmp, sizeof(tmp));	\
			ERRMSG("Error: " call ": %s", ## args, buf);	\
		}							\
	} while(0)
#endif

#define BUG_ON(condition)					\
	do {							\
		if (caa_unlikely(condition))			\
			ERR("condition not respected (BUG) on line %s:%d", __FILE__, __LINE__);	\
	} while(0)
#define WARN_ON(condition)					\
	do {							\
		if (caa_unlikely(condition))			\
			WARN("condition not respected on line %s:%d", __FILE__, __LINE__); \
	} while(0)
#define WARN_ON_ONCE(condition) WARN_ON(condition)

#endif /* _USTERR_SIGNAL_SAFE_H */
