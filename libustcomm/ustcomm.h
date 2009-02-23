#ifndef USTCOMM_H
#define USTCOMM_H

#include <sys/types.h>

int send_message(pid_t pid, const char *msg, const char *reply);

#endif /* USTCOMM_H */
