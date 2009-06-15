#ifndef LOCALERR_H
#define LOCALERR_H

#include <stdio.h>

#define DBG(fmt, args...) fprintf(stderr, "ust: " fmt "\n", ## args); fflush(stderr)
#define WARN(fmt, args...) fprintf(stderr, "ust: WARNING: " fmt "\n", ## args); fflush(stderr)
#define ERR(fmt, args...) fprintf(stderr, "ust: ERROR: " fmt "\n", ## args); fflush(stderr)
#define PERROR(a) perror(a)

#endif /* LOCALERR_H */
