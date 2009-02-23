#ifndef USTCOMM_H
#define USTCOMM_H

#include <sys/types.h>

struct ustcomm_app {
	/* the socket for serving the external requests */
	int fd;
	char *socketpath;
};

struct ustcomm_ustd {
	/* the socket for serving the external requests */
	int fd;
	char *socketpath;
};

int send_message(pid_t pid, const char *msg, char **reply);

int ustcomm_init_app(pid_t pid, struct ustcomm_app *handle);

int ustcomm_init_ustd(struct ustcomm_ustd *handle);

#endif /* USTCOMM_H */
