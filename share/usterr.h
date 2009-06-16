#ifndef USTERR_H
#define USTERR_H

//#define DEBUG
#ifdef DEBUG
# define DBG(fmt, args...) do { fprintf(stderr, fmt "\n", ## args); fflush(stderr); } while(0)
#else
# define DBG(fmt, args...) do {} while(0)
#endif
#define WARN(fmt, args...) fprintf(stderr, "libust: WARNING: " fmt "\n", ## args); fflush(stderr)
#define ERR(fmt, args...) fprintf(stderr, "libust: ERROR: " fmt "\n", ## args); fflush(stderr)
#define BUG(fmt, args...) fprintf(stderr, "libust: BUG: " fmt "\n", ## args); fflush(stderr)
#define PERROR(call) perror("ust: ERROR: " call)

#define BUG_ON(condition) do { if (unlikely(condition)) ERR("condition not respected (BUG)"); } while(0)
#define WARN_ON(condition) do { if (unlikely(condition)) WARN("condition not respected on line %s:%d", __FILE__, __LINE__); } while(0)

#endif /* USTERR_H */
