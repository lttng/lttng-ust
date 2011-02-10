/* Copyright (C) 2009  Pierre-Marc Fournier
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#ifndef USTERR_H
#define USTERR_H

#include <string.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>

#include <ust/core.h>

#include "share.h"

#ifndef UST_COMPONENT
//#error UST_COMPONENT is undefined
#define UST_COMPONENT libust
#endif

/* To stringify the expansion of a define */
#define XSTR(d) STR(d)
#define STR(s) #s

/* We sometimes print in the tracing path, and tracing can occur in
 * signal handlers, so we must use a print method which is signal safe.
 */

extern int ust_safe_snprintf(char *str, size_t n, const char *fmt, ...)
	__attribute__ ((format (printf, 3, 4)));

#define sigsafe_print_err(fmt, args...) \
{ \
	/* Can't use dynamic allocation. Limit ourselves to 250 chars. */ \
	char ____buf[250]; \
	int ____saved_errno; \
\
	/* Save the errno. */ \
	____saved_errno = errno; \
\
	ust_safe_snprintf(____buf, sizeof(____buf), fmt, ## args); \
\
	/* Add end of string in case of buffer overflow. */ \
	____buf[sizeof(____buf)-1] = 0; \
\
	patient_write(STDERR_FILENO, ____buf, strlen(____buf)); \
	/* Can't print errors because we are in the error printing code path. */ \
\
	/* Restore errno, in order to be async-signal safe. */ \
	errno = ____saved_errno; \
}

#define UST_STR_COMPONENT XSTR(UST_COMPONENT)

#define ERRMSG(fmt, args...) do { sigsafe_print_err(UST_STR_COMPONENT "[%ld/%ld]: " fmt " (in %s() at " __FILE__ ":" XSTR(__LINE__) ")\n", (long) getpid(), (long) syscall(SYS_gettid), ## args, __func__); fflush(stderr); } while(0)

#ifdef UST_DEBUG
# define DBG(fmt, args...) ERRMSG(fmt, ## args)
# define DBG_raw(fmt, args...) do { sigsafe_print_err(fmt, ## args); fflush(stderr); } while(0)
#else
# define DBG(fmt, args...) do {} while(0)
# define DBG_raw(fmt, args...) do {} while(0)
#endif
#define WARN(fmt, args...) ERRMSG("Warning: " fmt, ## args)
#define ERR(fmt, args...) ERRMSG("Error: " fmt, ## args)
#define BUG(fmt, args...) ERRMSG("BUG: " fmt, ## args)

#if (_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && !defined(_GNU_SOURCE)
#define PERROR(call, args...)\
	do { \
		char buf[200] = "Error in strerror_r()"; \
		strerror_r(errno, buf, sizeof(buf)); \
		ERRMSG("Error: " call ": %s", ## args, buf); \
	} while(0);
#else
#define PERROR(call, args...)\
	do { \
		char *buf; \
		char tmp[200]; \
		buf = strerror_r(errno, tmp, sizeof(tmp)); \
		ERRMSG("Error: " call ": %s", ## args, buf); \
	} while(0);
#endif

#define BUG_ON(condition) do { if (unlikely(condition)) ERR("condition not respected (BUG)"); } while(0)
#define WARN_ON(condition) do { if (unlikely(condition)) WARN("condition not respected on line %s:%d", __FILE__, __LINE__); } while(0)
#define WARN_ON_ONCE(condition) WARN_ON(condition)

#endif /* USTERR_H */
