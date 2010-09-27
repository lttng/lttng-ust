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

/* API used by UST components to communicate with each other via sockets. */

#define _GNU_SOURCE
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <execinfo.h>

#include "ustcomm.h"
#include "usterr.h"
#include "share.h"

static int mkdir_p(const char *path, mode_t mode)
{
	const char *path_p;
	char *tmp;

	int retval = 0;
	int result;
	mode_t old_umask;

	tmp = zmalloc(strlen(path) + 1);
	if (tmp == NULL)
		return -1;

	/* skip first / */
	path_p = path+1;

	old_umask = umask(0);
	for(;;) {
		while (*path_p != '/') {
			if(*path_p == 0)
				break;
			++path_p;
		}
		if (*path_p == '/') {
			strncpy(tmp, path, path_p - path);
			tmp[path_p-path] = '\0';
			if (tmp[path_p - path - 1] != '/') {
				result = mkdir(tmp, mode);
				if(result == -1) {
					if (!(errno == EEXIST || errno == EACCES || errno == EROFS)) {
						/* Then this is a real error */
						retval = -1;
						break;
					}
				}
			}
			/* pass / */
			path_p++;
		} else {
			/* last component */
			result = mkdir(path, mode);
			if (result == -1)
				retval = -1;
			break;
		}
	}

	free(tmp);
	umask(old_umask);
	return retval;
}

static struct sockaddr_un * create_sock_addr(const char *name,
					     size_t *sock_addr_size)
{
	struct sockaddr_un * addr;
	size_t alloc_size;

	alloc_size = (size_t) (((struct sockaddr_un *) 0)->sun_path) +
		strlen(name) + 1;

	addr = malloc(alloc_size);
	if (addr < 0) {
		ERR("allocating addr failed");
		return NULL;
	}

	addr->sun_family = AF_UNIX;
	strcpy(addr->sun_path, name);

	*sock_addr_size = alloc_size;

	return addr;
}

struct ustcomm_sock * ustcomm_init_sock(int fd, int epoll_fd,
					struct list_head *list)
{
	struct epoll_event ev;
	struct ustcomm_sock *sock;

	sock = malloc(sizeof(struct ustcomm_sock));
	if (!sock) {
		perror("malloc: couldn't allocate ustcomm_sock");
		return NULL;
	}

	ev.events = EPOLLIN;
	ev.data.ptr = sock;
	sock->fd = fd;

	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock->fd, &ev) == -1) {
		perror("epoll_ctl: failed to add socket\n");
		free(sock);
		return NULL;
	}

	sock->epoll_fd = epoll_fd;
	if (list) {
		list_add(&sock->list, list);
	} else {
		INIT_LIST_HEAD(&sock->list);
	}

	return sock;
}

void ustcomm_del_sock(struct ustcomm_sock *sock, int keep_in_epoll)
{
	list_del(&sock->list);
	if (!keep_in_epoll) {
		if (epoll_ctl(sock->epoll_fd, EPOLL_CTL_DEL, sock->fd, NULL) == -1) {
			PERROR("epoll_ctl: failed to delete socket");
		}
	}
	close(sock->fd);
	free(sock);
}

struct ustcomm_sock * ustcomm_init_named_socket(const char *name,
						int epoll_fd)
{
	int result;
	int fd;
	size_t sock_addr_size;
	struct sockaddr_un * addr;
	struct ustcomm_sock *sock;

	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if(fd == -1) {
		PERROR("socket");
		return NULL;
	}

	addr = create_sock_addr(name, &sock_addr_size);
	if (addr == NULL) {
		ERR("allocating addr, UST thread bailing");
		goto close_sock;
	}

	result = access(name, F_OK);
	if(result == 0) {
		/* file exists */
		result = unlink(name);
		if(result == -1) {
			PERROR("unlink of socket file");
			goto free_addr;
		}
		DBG("socket already exists; overwriting");
	}

	result = bind(fd, (struct sockaddr *)addr, sock_addr_size);
	if(result == -1) {
		PERROR("bind");
		goto free_addr;
	}

	result = listen(fd, 1);
	if(result == -1) {
		PERROR("listen");
		goto free_addr;
	}

	sock = ustcomm_init_sock(fd, epoll_fd,
				 NULL);
	if (!sock) {
		ERR("failed to create ustcomm_sock");
		goto free_addr;
	}

	free(addr);

	return sock;

free_addr:
	free(addr);
close_sock:
	close(fd);

	return NULL;
}

void ustcomm_del_named_sock(struct ustcomm_sock *sock,
			    int keep_socket_file)
{
	int result, fd;
	struct stat st;
	struct sockaddr dummy;
	struct sockaddr_un *sockaddr = NULL;
	int alloc_size;

	fd = sock->fd;

	if(!keep_socket_file) {

		/* Get the socket name */
		alloc_size = sizeof(dummy);
		if (getsockname(fd, &dummy, (socklen_t *)&alloc_size) < 0) {
			PERROR("getsockname failed");
			goto del_sock;
		}

		sockaddr = zmalloc(alloc_size);
		if (!sockaddr) {
			ERR("failed to allocate sockaddr");
			goto del_sock;
		}

		if (getsockname(fd, sockaddr, (socklen_t *)&alloc_size) < 0) {
			PERROR("getsockname failed");
			goto free_sockaddr;
		}

		/* Destroy socket */
		result = stat(sockaddr->sun_path, &st);
		if(result < 0) {
			PERROR("stat (%s)", sockaddr->sun_path);
			goto free_sockaddr;
		}

		/* Paranoid check before deleting. */
		result = S_ISSOCK(st.st_mode);
		if(!result) {
			ERR("The socket we are about to delete is not a socket.");
			goto free_sockaddr;
		}

		result = unlink(sockaddr->sun_path);
		if(result < 0) {
			PERROR("unlink");
		}
	}

free_sockaddr:
	free(sockaddr);

del_sock:
	ustcomm_del_sock(sock, keep_socket_file);
}


/* Called by an app to ask the consumer daemon to connect to it. */

int ustcomm_request_consumer(pid_t pid, const char *channel)
{
	int result, daemon_fd;
	int retval = 0;
	char *msg=NULL;
	char *explicit_daemon_socket_path, *daemon_path;

	explicit_daemon_socket_path = getenv("UST_DAEMON_SOCKET");
	if (explicit_daemon_socket_path) {
		/* user specified explicitly a socket path */
		result = asprintf(&daemon_path, "%s", explicit_daemon_socket_path);
	} else {
		/* just use the default path */
		result = asprintf(&daemon_path, "%s/ustd", SOCK_DIR);
	}
	if (result < 0) {
		ERR("string overflow allocating socket name");
		return -1;
	}

	if (asprintf(&msg, "collect %d %s", pid, channel) < 0) {
		ERR("ustcomm_request_consumer : asprintf failed (collect %d/%s)",
		    pid, channel);
		retval = -1;
		goto free_daemon_path;
	}

	result = ustcomm_connect_path(daemon_path, &daemon_fd);
	if (result < 0) {
		WARN("ustcomm_connect_path failed, daemon_path: %s",
		     daemon_path);
		retval = -1;
		goto del_string;
	}

	result = ustcomm_send_request(daemon_fd, msg, NULL);
	if (result < 0) {
		WARN("ustcomm_send_request failed, daemon path: %s",
		     daemon_path);
		retval = -1;
	}

	close(daemon_fd);
del_string:
	free(msg);
free_daemon_path:
	free(daemon_path);

	return retval;
}

/* returns 1 to indicate a message was received
 * returns 0 to indicate no message was received (end of stream)
 * returns -1 to indicate an error
 */
int ustcomm_recv_fd(int sock,
		    struct ustcomm_header *header,
		    char **data, int *fd)
{
	int result;
	int retval;
	struct ustcomm_header peek_header;
	struct iovec iov[2];
	struct msghdr msg;
	struct cmsghdr *cmsg;
	char buf[CMSG_SPACE(sizeof(int))];

	result = recv(sock, &peek_header, sizeof(peek_header),
		      MSG_PEEK | MSG_WAITALL);
	if (result <= 0) {
		if(errno == ECONNRESET) {
			return 0;
		} else if (errno == EINTR) {
			return -1;
		} else if (result < 0) {
			PERROR("recv");
			return -1;
		}
		return 0;
	}

	memset(&msg, 0, sizeof(msg));

	iov[0].iov_base = (char *)header;
	iov[0].iov_len = sizeof(struct ustcomm_header);

	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	if (peek_header.size) {
		if (peek_header.size < 0 || peek_header.size > 100) {
			WARN("big peek header! %d", peek_header.size);
		}
		*data = malloc(peek_header.size);
		if (!*data) {
			ERR("failed to allocate space for message");
		}

		iov[1].iov_base = (char *)*data;
		iov[1].iov_len = peek_header.size;

		msg.msg_iovlen++;
	}

	if (fd && peek_header.fd_included) {
		msg.msg_control = buf;
		msg.msg_controllen = sizeof(buf);
	}

	result = recvmsg(sock, &msg,
			 MSG_WAITALL);

	if (result <= 0) {
		if(errno == ECONNRESET) {
			retval = 0;
		} else if (errno == EINTR) {
			retval = -1;
		} else if (result < 0) {
			PERROR("recv");
			retval = -1;
		} else {
			retval = 0;
		}
		free(*data);
		return retval;
	}

	if (fd && peek_header.fd_included) {
		cmsg = CMSG_FIRSTHDR(&msg);
		result = 0;
		while (cmsg != NULL) {
			if (cmsg->cmsg_level == SOL_SOCKET
			    && cmsg->cmsg_type  == SCM_RIGHTS) {
				*fd = *(int *) CMSG_DATA(cmsg);
				result = 1;
				break;
			}
			cmsg = CMSG_NXTHDR(&msg, cmsg);
		}
		if (!result) {
			ERR("Failed to receive file descriptor\n");
		}
	}

	return 1;
}

int ustcomm_recv(int sock,
		 struct ustcomm_header *header,
		 char **data)
{
	return ustcomm_recv_fd(sock, header, data, NULL);
}


int recv_message_conn(int sock, char **msg)
{
	struct ustcomm_header header;

	return ustcomm_recv(sock, &header, msg);
}

int ustcomm_send_fd(int sock,
		    const struct ustcomm_header *header,
		    const char *data,
		    int *fd)
{
	struct iovec iov[2];
	struct msghdr msg;
	int result;
	struct cmsghdr *cmsg;
	char buf[CMSG_SPACE(sizeof(int))];

	memset(&msg, 0, sizeof(msg));

	iov[0].iov_base = (char *)header;
	iov[0].iov_len = sizeof(struct ustcomm_header);

	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	if (header->size) {
		iov[1].iov_base = (char *)data;
		iov[1].iov_len = header->size;

		msg.msg_iovlen++;

	}

	if (fd && header->fd_included) {
		msg.msg_control = buf;
		msg.msg_controllen = sizeof(buf);
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		*(int *) CMSG_DATA(cmsg) = *fd;
		msg.msg_controllen = cmsg->cmsg_len;
	}

	result = sendmsg(sock, &msg, MSG_NOSIGNAL);
	if (result < 0 && errno != EPIPE) {
		PERROR("sendmsg failed");
	}
	return result;
}

int ustcomm_send(int sock,
		 const struct ustcomm_header *header,
		 const char *data)
{
	return ustcomm_send_fd(sock, header, data, NULL);
}

int ustcomm_send_reply(char *msg, int sock)
{
	int result;
	struct ustcomm_header header;

	memset(&header, 0, sizeof(header));

	header.size = strlen(msg) + 1;

	result = ustcomm_send(sock, &header, msg);
	if(result < 0) {
		ERR("error in ustcomm_send");
		return result;
	}

	return 0;
}

int ustcomm_send_req(int sock,
		     const struct ustcomm_header *req_header,
		     const char *data,
		     char **response)
{
	int result;
	struct ustcomm_header res_header;

	result = ustcomm_send(sock, req_header, data);
	if ( result <= 0) {
		return result;
	}

	if (!response) {
		return 1;
	}

	return ustcomm_recv(sock,
			    &res_header,
			    response);

}

/*
 * Return value:
 *   0: Success, but no reply because recv() returned 0
 *   1: Success
 *   -1: Error
 *
 * On error, the error message is printed, except on
 * ECONNRESET, which is normal when the application dies.
 */

int ustcomm_send_request(int sock, const char *req, char **reply)
{
	struct ustcomm_header req_header;

	req_header.size = strlen(req) + 1;

	return ustcomm_send_req(sock,
				&req_header,
				req,
				reply);

}

/* Return value:
 *  0: success
 * -1: error
 */

int ustcomm_connect_path(const char *name, int *connection_fd)
{
	int result, fd;
	size_t sock_addr_size;
	struct sockaddr_un *addr;

	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if(fd == -1) {
		PERROR("socket");
		return -1;
	}

	addr = create_sock_addr(name, &sock_addr_size);
	if (addr == NULL) {
		ERR("allocating addr failed");
		goto close_sock;
	}

	result = connect(fd, (struct sockaddr *)addr, sock_addr_size);
	if(result == -1) {
		PERROR("connect (path=%s)", name);
		goto free_sock_addr;
	}

	*connection_fd = fd;

	free(addr);

	return 0;

free_sock_addr:
	free(addr);
close_sock:
	close(fd);

	return -1;
}


/* Open a connection to a traceable app.
 *
 * Return value:
 *  0: success
 * -1: error
 */

int ustcomm_connect_app(pid_t pid, int *app_fd)
{
	int result;
	int retval = 0;
	char *name;

	result = asprintf(&name, "%s/%d", SOCK_DIR, pid);
	if (result < 0) {
		ERR("failed to allocate socket name");
		return -1;
	}

	result = ustcomm_connect_path(name, app_fd);
	if (result < 0) {
		ERR("failed to connect to app");
		retval = -1;
	}

	free(name);

	return retval;
}

int ensure_dir_exists(const char *dir)
{
	struct stat st;
	int result;

	if(!strcmp(dir, ""))
		return -1;

	result = stat(dir, &st);
	if(result == -1 && errno != ENOENT) {
		return -1;
	}
	else if(result == -1) {
		/* ENOENT */
		int result;

		/* mkdir mode to 0777 */
		result = mkdir_p(dir, S_IRWXU | S_IRWXG | S_IRWXO);
		if(result != 0) {
			ERR("executing in recursive creation of directory %s", dir);
			return -1;
		}
	}

	return 0;
}

/* Used by the daemon to initialize its server so applications
 * can connect to it.
 */


static const char *find_tok(const char *str)
{
	while(*str == ' ') {
		str++;

		if(*str == 0)
			return NULL;
	}

	return str;
}

static const char *find_sep(const char *str)
{
	while(*str != ' ') {
		str++;

		if(*str == 0)
			break;
	}

	return str;
}

int nth_token_is(const char *str, const char *token, int tok_no)
{
	int i;
	const char *start;
	const char *end;

	for(i=0; i<=tok_no; i++) {
		str = find_tok(str);
		if(str == NULL)
			return -1;

		start = str;

		str = find_sep(str);
		if(str == NULL)
			return -1;

		end = str;
	}

	if(end-start != strlen(token))
		return 0;

	if(strncmp(start, token, end-start))
		return 0;

	return 1;
}

char *nth_token(const char *str, int tok_no)
{
	static char *retval = NULL;
	int i;
	const char *start;
	const char *end;

	for(i=0; i<=tok_no; i++) {
		str = find_tok(str);
		if(str == NULL)
			return NULL;

		start = str;

		str = find_sep(str);
		if(str == NULL)
			return NULL;

		end = str;
	}

	if(retval) {
		free(retval);
		retval = NULL;
	}

	if (asprintf(&retval, "%.*s", (int)(end-start), start) < 0) {
		ERR("nth_token : asprintf failed (%.*s)",
		    (int)(end-start), start);
		return NULL;
	}

	return retval;
}
