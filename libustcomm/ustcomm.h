/* Copyright (C) 2009  Pierre-Marc Fournier
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#ifndef USTCOMM_H
#define USTCOMM_H

#include <sys/types.h>
#include <sys/un.h>

#include "kcompat.h"

#define SOCK_DIR "/tmp/socks"
#define UST_SIGNAL SIGIO

struct ustcomm_connection {
	struct list_head list;
	int fd;
};

/* ustcomm_server must be shallow-copyable */
struct ustcomm_server {
	/* the "server" socket for serving the external requests */
	int listen_fd;
	char *socketpath;

	struct list_head connections;
};

struct ustcomm_ustd {
	struct ustcomm_server server;
};

struct ustcomm_app {
	struct ustcomm_server server;
};

/* ustcomm_source must be shallow-copyable */
struct ustcomm_source {
	int fd;
	void *priv;
};

char *strdup_malloc(const char *s);

//int send_message_pid(pid_t pid, const char *msg, char **reply);
int ustcomm_request_consumer(pid_t pid, const char *channel);

int ustcomm_ustd_recv_message(struct ustcomm_ustd *ustd, char **msg, struct ustcomm_source *src, int timeout);
int ustcomm_app_recv_message(struct ustcomm_app *app, char **msg, struct ustcomm_source *src, int timeout);

int ustcomm_init_app(pid_t pid, struct ustcomm_app *handle);

int ustcomm_init_ustd(struct ustcomm_ustd *handle);

int ustcomm_connect_app(pid_t pid, struct ustcomm_connection *conn);
int ustcomm_send_request(struct ustcomm_connection *conn, const char *req, char **reply);
int ustcomm_send_reply(struct ustcomm_server *server, char *msg, struct ustcomm_source *src);

int nth_token_is(char *str, char *token, int tok_no);

char *nth_token(char *str, int tok_no);

int pid_is_online(pid_t);

#endif /* USTCOMM_H */
