#include <stdio.h>

//#define DEBUG
#ifdef DEBUG
# define DBG(fmt, args...) fprintf(stderr, "ustd: " fmt "\n", ## args); fflush(stderr)
#else
# define DBG(fmt, args...) do {} while(0)
#endif

#define WARN(fmt, args...) fprintf(stderr, "ustd: WARNING: " fmt "\n", ## args); fflush(stderr)
#define ERR(fmt, args...) fprintf(stderr, "ustd: ERROR: " fmt "\n", ## args); fflush(stderr)
#define PERROR(a) perror(a)
