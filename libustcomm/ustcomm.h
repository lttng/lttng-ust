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
#include <urcu/list.h>

#include <ust/kcompat/kcompat.h>

#define SOCK_DIR "/tmp/ust-app-socks"
#define UST_SIGNAL SIGIO

struct ustcomm_sock {
	struct list_head list;
	int fd;
	int epoll_fd;
};

struct ustcomm_header {
	int type;
	long size;
	int command;
	int response;
	int fd_included;
};


//int send_message_pid(pid_t pid, const char *msg, char **reply);

/* Ensure directory existence, usefull for unix sockets */
extern int ensure_dir_exists(const char *dir);

/* Create and delete sockets */
extern struct ustcomm_sock * ustcomm_init_sock(int fd, int epoll_fd,
					       struct list_head *list);
extern void ustcomm_del_sock(struct ustcomm_sock *sock, int keep_in_epoll);

/* Create and delete named sockets */
extern struct ustcomm_sock * ustcomm_init_named_socket(const char *name,
						       int epoll_fd);
extern void ustcomm_del_named_sock(struct ustcomm_sock *sock,
				   int keep_socket_file);

/* Send and receive functions for file descriptors */
extern int ustcomm_send_fd(int sock, const struct ustcomm_header *header,
			   const char *data, int *fd);
extern int ustcomm_recv_fd(int sock, struct ustcomm_header *header,
			   char **data, int *fd);

/* Normal send and receive functions */
extern int ustcomm_send(int sock, const struct ustcomm_header *header,
			const char *data);
extern int ustcomm_recv(int sock, struct ustcomm_header *header,
			char **data);


extern int ustcomm_request_consumer(pid_t pid, const char *channel);
extern int ustcomm_connect_app(pid_t pid, int *app_fd);
extern int ustcomm_connect_path(const char *path, int *connection_fd);
extern int ustcomm_send_request(int sock, const char *req, char **reply);
extern int ustcomm_send_reply(char *msg, int sock);
extern int recv_message_conn(int sock, char **msg);
extern int nth_token_is(const char *str, const char *token, int tok_no);

extern char *nth_token(const char *str, int tok_no);

#endif /* USTCOMM_H */
