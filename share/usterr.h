#ifndef USTERR_H
#define USTERR_H

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
# define DBG(fmt, args...) do { fprintf(stderr, UST_STR_COMPONENT ": " fmt "(" __FILE__ ":" XSTR(__LINE__) ")\n", ## args); fflush(stderr); } while(0)
#else
# define DBG(fmt, args...) do {} while(0)
#endif
#define WARN(fmt, args...) fprintf(stderr, UST_STR_COMPONENT ": Warning: " fmt "\n", ## args); fflush(stderr)
#define ERR(fmt, args...) fprintf(stderr, UST_STR_COMPONENT ": Error: " fmt "\n", ## args); fflush(stderr)
#define BUG(fmt, args...) fprintf(stderr, UST_STR_COMPONENT ": BUG: " fmt "\n", ## args); fflush(stderr)
#define PERROR(call) perror("ust: ERROR: " call)

#define BUG_ON(condition) do { if (unlikely(condition)) ERR("condition not respected (BUG)"); } while(0)
#define WARN_ON(condition) do { if (unlikely(condition)) WARN("condition not respected on line %s:%d", __FILE__, __LINE__); } while(0)

#endif /* USTERR_H */
