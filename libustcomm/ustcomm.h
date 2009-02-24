#ifndef USTCOMM_H
#define USTCOMM_H

#include <sys/types.h>

struct ustcomm_app {
	/* the "server" socket for serving the external requests */
	int fd;
	char *socketpath;
};

struct ustcomm_ustd {
	/* the "server" socket for serving the external requests */
	int fd;
	char *socketpath;
};

int send_message(pid_t pid, const char *msg, char **reply);

int ustcomm_ustd_recv_message(struct ustcomm_ustd *ustd, char **msg);
int ustcomm_app_recv_message(struct ustcomm_app *app, char **msg);

int ustcomm_init_app(pid_t pid, struct ustcomm_app *handle);

int ustcomm_init_ustd(struct ustcomm_ustd *handle);

#endif /* USTCOMM_H */
