#ifndef USTCOMM_H
#define USTCOMM_H

#include <sys/types.h>
#include <sys/un.h>

#include "kcompat.h"

struct ustcomm_connection {
	struct list_head list;
	int fd;
};

struct ustcomm_app {
	/* the "server" socket for serving the external requests */
	int listen_fd;
	char *socketpath;

	struct list_head connections;
};

struct ustcomm_ustd {
	/* the "server" socket for serving the external requests */
	int listen_fd;
	char *socketpath;

	struct list_head connections;
};

struct ustcomm_source {
	struct sockaddr_un addr;
};

int send_message(pid_t pid, const char *msg, char **reply);

int ustcomm_ustd_recv_message(struct ustcomm_ustd *ustd, char **msg, struct ustcomm_source *src);
int ustcomm_app_recv_message(struct ustcomm_app *app, char **msg, struct ustcomm_source *src);

int ustcomm_init_app(pid_t pid, struct ustcomm_app *handle);

int ustcomm_init_ustd(struct ustcomm_ustd *handle);

int nth_token_is(char *str, char *token, int tok_no);

char *nth_token(char *str, int tok_no);

#endif /* USTCOMM_H */
