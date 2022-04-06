/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2009 Pierre-Marc Fournier
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _UST_COMMON_LOGGING_H
#define _UST_COMMON_LOGGING_H

#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>

#include <lttng/ust-utils.h>
#include <urcu/compiler.h>
#include <urcu/system.h>

#include "common/patient.h"
#include "common/compat/tid.h"
#include "common/safe-snprintf.h"

enum lttng_ust_log_level {
	LTTNG_UST_LOG_LEVEL_UNKNOWN = 0,
	LTTNG_UST_LOG_LEVEL_SILENT,
	LTTNG_UST_LOG_LEVEL_DEBUG,
};

enum lttng_ust_log_critical_action {
	LTTNG_UST_LOG_CRITICAL_ACTION_UNKNOWN = 0,
	LTTNG_UST_LOG_CRITICAL_ACTION_NONE,
	LTTNG_UST_LOG_CRITICAL_ACTION_ABORT,
};

extern int lttng_ust_log_level			/* enum lttng_ust_log_level */
	__attribute__((visibility("hidden")));

extern int lttng_ust_log_critical_action		/* enum lttng_ust_log_critical_action */
	__attribute__((visibility("hidden")));

/*
 * Initialize the global log level from the "LTTNG_UST_DEBUG" environment
 * variable and the global log critical action from "LTTNG_UST_ABORT_ON_CRITICAL".
 *
 * This could end up being called concurrently by multiple threads but doesn't
 * require a mutex since the input is invariant across threads and the result
 * will be the same.
 */
void lttng_ust_logging_init(void)
	__attribute__((visibility("hidden")));

#ifdef LTTNG_UST_DEBUG
static inline
bool lttng_ust_logging_debug_enabled(void)
{
	return true;
}
#else /* #ifdef LTTNG_UST_DEBUG */
static inline
bool lttng_ust_logging_debug_enabled(void)
{
	int current_log_level;

	current_log_level = CMM_LOAD_SHARED(lttng_ust_log_level);

	/* If the global log level is unknown, lazy-initialize it. */
	if (caa_unlikely(current_log_level == LTTNG_UST_LOG_LEVEL_UNKNOWN)) {
		lttng_ust_logging_init();
		current_log_level = CMM_LOAD_SHARED(lttng_ust_log_level);
	}

	return current_log_level == LTTNG_UST_LOG_LEVEL_DEBUG;
}
#endif /* #ifdef LTTNG_UST_DEBUG */

#ifdef LTTNG_UST_ABORT_ON_CRITICAL
static inline
bool lttng_ust_logging_abort_on_critical_enabled(void)
{
	return true;
}
#else /* #ifdef LTTNG_UST_ABORT_ON_CRITICAL */
static inline
bool lttng_ust_logging_abort_on_critical_enabled(void)
{
	int current_log_critical_action;

	current_log_critical_action = CMM_LOAD_SHARED(lttng_ust_log_critical_action);

	/* If the global log critical action is unknown, lazy-initialize it. */
	if (caa_unlikely(current_log_critical_action == LTTNG_UST_LOG_CRITICAL_ACTION_UNKNOWN)) {
		lttng_ust_logging_init();
		current_log_critical_action = CMM_LOAD_SHARED(lttng_ust_log_critical_action);
	}

	return current_log_critical_action == LTTNG_UST_LOG_CRITICAL_ACTION_ABORT;
}
#endif /* #ifdef LTTNG_UST_ABORT_ON_CRITICAL */

/*
 * The default component for log statements.
 */
#ifndef UST_COMPONENT
#define UST_COMPONENT libust
#endif

#define LTTNG_UST_LOG_MAX_LEN	512

/*
 * We sometimes print in the tracing path, and tracing can occur in
 * signal handlers, so we must use a print method which is signal safe.
 */
/* Can't use dynamic allocation. Limit ourselves to LTTNG_UST_LOG_MAX_LEN chars. */
/* Add end of string in case of buffer overflow. */
#define sigsafe_print_err(fmt, args...)					\
do {									\
	if (lttng_ust_logging_debug_enabled()) {			\
		char ____buf[LTTNG_UST_LOG_MAX_LEN];			\
		int ____saved_errno;					\
									\
		____saved_errno = errno;	/* signal-safety */	\
		ust_safe_snprintf(____buf, sizeof(____buf), fmt, ## args); \
		____buf[sizeof(____buf) - 1] = 0;			\
		ust_patient_write(STDERR_FILENO, ____buf, strlen(____buf)); \
		errno = ____saved_errno;	/* signal-safety */	\
	}								\
} while (0)

#define LTTNG_UST_STR_COMPONENT lttng_ust_stringify(UST_COMPONENT)

#define ERRMSG(fmt, args...)			\
	do {					\
		sigsafe_print_err(LTTNG_UST_STR_COMPONENT "[%ld/%ld]: " fmt " (in %s() at " __FILE__ ":" lttng_ust_stringify(__LINE__) ")\n", \
		(long) getpid(),		\
		(long) lttng_gettid(),		\
		## args, __func__);		\
	} while(0)


#define DBG(fmt, args...)	ERRMSG(fmt, ## args)
#define DBG_raw(fmt, args...)	sigsafe_print_err(fmt, ## args)
#define WARN(fmt, args...)	ERRMSG("Warning: " fmt, ## args)
#define ERR(fmt, args...)	ERRMSG("Error: " fmt, ## args)
#define CRIT(fmt, args...)						\
	do {								\
		ERRMSG("Critical: " fmt, ## args);			\
		if (lttng_ust_logging_abort_on_critical_enabled()) {	\
			abort();					\
		}							\
	} while(0)

#if !defined(__GLIBC__) || ((_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && !defined(_GNU_SOURCE))
/*
 * Version using XSI strerror_r.
 */
#define PERROR(call, args...)						\
	do {								\
		if (lttng_ust_logging_debug_enabled()) {		\
			char perror_buf[200] = "Error in strerror_r()";	\
			strerror_r(errno, perror_buf,			\
					sizeof(perror_buf));		\
			ERRMSG("Error: " call ": %s", ## args, 		\
					perror_buf);			\
		}							\
	} while(0)
#else
/*
 * Version using GNU strerror_r, for linux with appropriate defines.
 */
#define PERROR(call, args...)						\
	do {								\
		if (lttng_ust_logging_debug_enabled()) {		\
			char *perror_buf;				\
			char perror_tmp[200];				\
			perror_buf = strerror_r(errno, perror_tmp,	\
					sizeof(perror_tmp));		\
			ERRMSG("Error: " call ": %s", ## args,		\
					perror_buf);			\
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

#endif /* _UST_COMMON_LOGGING_H */
