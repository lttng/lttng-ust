#ifndef USTERR_H
#define USTERR_H

#include <string.h>

#ifndef UST_COMPONENT
//#error UST_COMPONENT is undefined
#define UST_COMPONENT libust
#endif

/* To stringify the expansion of a define */
#define XSTR(d) STR(d)
#define STR(s) #s

#define UST_STR_COMPONENT XSTR(UST_COMPONENT)

#define DEBUG
#ifdef DEBUG
# define DBG(fmt, args...) do { fprintf(stderr, UST_STR_COMPONENT ": " fmt " (" __FILE__ ":" XSTR(__LINE__) ")\n", ## args); fflush(stderr); } while(0)
#else
# define DBG(fmt, args...) do {} while(0)
#endif
#define WARN(fmt, args...) fprintf(stderr, UST_STR_COMPONENT ": Warning: " fmt "\n", ## args); fflush(stderr)
#define ERR(fmt, args...) fprintf(stderr, UST_STR_COMPONENT ": Error: " fmt "\n", ## args); fflush(stderr)
#define BUG(fmt, args...) fprintf(stderr, UST_STR_COMPONENT ": BUG: " fmt "\n", ## args); fflush(stderr)

#if (_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && !defined(_GNU_SOURCE)
#define PERROR(call, args...)\
	do { \
		char buf[200] = "Error in strerror_r()"; \
		strerror_r(errno, buf, sizeof(buf)); \
		fprintf(stderr, UST_STR_COMPONENT ": Error: " call ": %s\n", ## args, buf); fflush(stderr); \
	} while(0);
#else
#define PERROR(call, args...)\
	do { \
		char *buf; \
		char tmp[200]; \
		buf = strerror_r(errno, tmp, sizeof(tmp)); \
		fprintf(stderr, UST_STR_COMPONENT ": Error: " call ": %s\n", ## args, buf); fflush(stderr); \
	} while(0);
#endif

#define BUG_ON(condition) do { if (unlikely(condition)) ERR("condition not respected (BUG)"); } while(0)
#define WARN_ON(condition) do { if (unlikely(condition)) WARN("condition not respected on line %s:%d", __FILE__, __LINE__); } while(0)

#endif /* USTERR_H */
