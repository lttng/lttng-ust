#ifndef USTERR_H
#define USTERR_H

#define DBG(fmt, args...) fprintf(stderr, fmt "\n", ## args); fflush(stderr)
#define WARN(fmt, args...) fprintf(stderr, "usertrace: WARNING: " fmt "\n", ## args); fflush(stderr)
#define ERR(fmt, args...) fprintf(stderr, "usertrace: ERROR: " fmt "\n", ## args); fflush(stderr)
#define BUG(fmt, args...) fprintf(stderr, "usertrace: BUG: " fmt "\n", ## args); fflush(stderr)
#define PERROR(call) perror("usertrace: ERROR: " call)

#define BUG_ON(condition) do { if (unlikely(condition)) ERR("condition not respected (BUG)"); } while(0)
#define WARN_ON(condition) do { if (unlikely(condition)) WARN("condition not respected on line %s:%d", __FILE__, __LINE__); } while(0)

#endif /* USTERR_H */
