#ifndef USTERR_H
#define USTERR_H

#include <string.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>

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

#define sigsafe_print_err(fmt, args...) \
{ \
	/* Can't use dynamic allocation. Limit ourselves to 250 chars. */ \
	char ____buf[250]; \
	int ____saved_errno; \
\
	/* Save the errno. */ \
	____saved_errno = errno; \
\
	snprintf(____buf, sizeof(____buf), fmt, ## args); \
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

#endif /* USTERR_H */
