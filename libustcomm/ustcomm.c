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

#define _GNU_SOURCE
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <poll.h>
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <execinfo.h>

#include "ustcomm.h"
#include "usterr.h"

#define UNIX_PATH_MAX 108

#define MSG_MAX 10000

/* FIXME: ustcomm blocks on message sending, which might be problematic in
 * some cases. Fix the poll() usage so sends are buffered until they don't
 * block.
 */

//static void bt(void)
//{
//	void *buffer[100];
//	int result;
//
//	result = backtrace(&buffer, 100);
//	backtrace_symbols_fd(buffer, result, STDERR_FILENO);
//}

char *strdup_malloc(const char *s)
{
	char *retval;

	if(s == NULL)
		return NULL;

	retval = (char *) malloc(strlen(s)+1);

	strcpy(retval, s);

	return retval;
}

static int signal_process(pid_t pid)
{
	return 0;
}

int pid_is_online(pid_t pid) {
	return 1;
}

static int send_message_fd(int fd, const char *msg)
{
	int result;

	result = send(fd, msg, strlen(msg), MSG_NOSIGNAL);
	if(result == -1) {
		PERROR("send");
		return -1;
	}
	else if(result == 0) {
		return 0;
	}

	return 1;
}

/* Called by an app to ask the consumer daemon to connect to it. */

int ustcomm_request_consumer(pid_t pid, const char *channel)
{
	char path[UNIX_PATH_MAX];
	int result;
	char *msg=NULL;
	int retval = 0;
	struct ustcomm_connection conn;
	char *explicit_daemon_socket_path;

	explicit_daemon_socket_path = getenv("UST_DAEMON_SOCKET");
	if(explicit_daemon_socket_path) {
		/* user specified explicitly a socket path */
		result = snprintf(path, UNIX_PATH_MAX, "%s", explicit_daemon_socket_path);
	}
	else {
		/* just use the default path */
		result = snprintf(path, UNIX_PATH_MAX, "%s/ustd", SOCK_DIR);
	}

	if(result >= UNIX_PATH_MAX) {
		ERR("string overflow allocating socket name");
		return -1;
	}

	asprintf(&msg, "collect %d %s", pid, channel); 

	/* don't signal it because it's the daemon */
	result = ustcomm_connect_path(path, &conn, -1);
	if(result == -1) {
		WARN("ustcomm_connect_path failed");
		retval = -1;
		goto del_string;
	}

	result = ustcomm_send_request(&conn, msg, NULL);
	if(result == -1) {
		WARN("ustcomm_send_request failed");
		retval = -1;
		goto disconnect;
	}

	disconnect:
	ustcomm_disconnect(&conn);
	del_string:
	free(msg);

	return retval;
}

/* returns 1 to indicate a message was received
 * returns 0 to indicate no message was received (cannot happen)
 * returns -1 to indicate an error
 */

static int recv_message_fd(int fd, char **msg, struct ustcomm_source *src)
{
	int result;

	*msg = (char *) malloc(MSG_MAX+1);

	result = recv(fd, *msg, MSG_MAX, 0);
	if(result == -1) {
		PERROR("recv");
		return -1;
	}

	(*msg)[result] = '\0';
	
	DBG("ustcomm_app_recv_message: result is %d, message is %s", result, (*msg));

	if(src)
		src->fd = fd;

	return 1;
}

int ustcomm_send_reply(struct ustcomm_server *server, char *msg, struct ustcomm_source *src)
{
	int result;

	result = send_message_fd(src->fd, msg);
	if(result < 0) {
		ERR("error in send_message_fd");
		return -1;
	}

	return 0;
} 

/* Called after a fork. */

int ustcomm_close_all_connections(struct ustcomm_server *server)
{
	struct ustcomm_connection *conn;
	struct ustcomm_connection *deletable_conn = NULL;

	list_for_each_entry(conn, &server->connections, list) {
		free(deletable_conn);
		deletable_conn = conn;
		close(conn->fd);
		list_del(&conn->list);
	}

	return 0;
}

/* @timeout: max blocking time in milliseconds, -1 means infinity
 *
 * returns 1 to indicate a message was received
 * returns 0 to indicate no message was received
 * returns -1 to indicate an error
 */

int ustcomm_recv_message(struct ustcomm_server *server, char **msg, struct ustcomm_source *src, int timeout)
{
	struct pollfd *fds;
	struct ustcomm_connection *conn;
	int result;
	int retval;

	for(;;) {
		int idx = 0;
		int n_fds = 1;

		list_for_each_entry(conn, &server->connections, list) {
			n_fds++;
		}

		fds = (struct pollfd *) malloc(n_fds * sizeof(struct pollfd));
		if(fds == NULL) {
			ERR("malloc returned NULL");
			return -1;
		}

		/* special idx 0 is for listening socket */
		fds[idx].fd = server->listen_fd;
		fds[idx].events = POLLIN;
		idx++;

		list_for_each_entry(conn, &server->connections, list) {
			fds[idx].fd = conn->fd;
			fds[idx].events = POLLIN;
			idx++;
		}

		while((result = poll(fds, n_fds, timeout)) == -1 && errno == EINTR)
			/* nothing */;
		if(result == -1) {
			PERROR("poll");
			return -1;
		}

		if(result == 0)
			return 0;

		if(fds[0].revents) {
			struct ustcomm_connection *newconn;
			int newfd;

			result = newfd = accept(server->listen_fd, NULL, NULL);
			if(result == -1) {
				PERROR("accept");
				return -1;
			}

			newconn = (struct ustcomm_connection *) malloc(sizeof(struct ustcomm_connection));
			if(newconn == NULL) {
				ERR("malloc returned NULL");
				return -1;
			}

			newconn->fd = newfd;

			list_add(&newconn->list, &server->connections);
		}

		for(idx=1; idx<n_fds; idx++) {
			if(fds[idx].revents) {
				retval = recv_message_fd(fds[idx].fd, msg, src);
				if(**msg == 0) {
					/* connection finished */
					close(fds[idx].fd);

					list_for_each_entry(conn, &server->connections, list) {
						if(conn->fd == fds[idx].fd) {
							list_del(&conn->list);
							break;
						}
					}
				}
				else {
					goto free_fds_return;
				}
			}
		}

		free(fds);
	}

free_fds_return:
	free(fds);
	return retval;
}

int ustcomm_ustd_recv_message(struct ustcomm_ustd *ustd, char **msg, struct ustcomm_source *src, int timeout)
{
	return ustcomm_recv_message(&ustd->server, msg, src, timeout);
}

int ustcomm_app_recv_message(struct ustcomm_app *app, char **msg, struct ustcomm_source *src, int timeout)
{
	return ustcomm_recv_message(&app->server, msg, src, timeout);
}

/* This removes src from the list of active connections of app.
 */

int ustcomm_app_detach_client(struct ustcomm_app *app, struct ustcomm_source *src)
{
	struct ustcomm_server *server = (struct ustcomm_server *)app;
	struct ustcomm_connection *conn;

	list_for_each_entry(conn, &server->connections, list) {
		if(conn->fd == src->fd) {
			list_del(&conn->list);
			goto found;
		}
	}

	return -1;
found:
	return src->fd;
}

static int init_named_socket(const char *name, char **path_out)
{
	int result;
	int fd;

	struct sockaddr_un addr;
	
	result = fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if(result == -1) {
		PERROR("socket");
		return -1;
	}

	addr.sun_family = AF_UNIX;

	strncpy(addr.sun_path, name, UNIX_PATH_MAX);
	addr.sun_path[UNIX_PATH_MAX-1] = '\0';

	result = access(name, F_OK);
	if(result == 0) {
		/* file exists */
		result = unlink(name);
		if(result == -1) {
			PERROR("unlink of socket file");
			goto close_sock;
		}
		WARN("socket already exists; overwriting");
	}

	result = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if(result == -1) {
		PERROR("bind");
		goto close_sock;
	}

	result = listen(fd, 1);
	if(result == -1) {
		PERROR("listen");
		goto close_sock;
	}

	if(path_out) {
		*path_out = strdup(addr.sun_path);
	}

	return fd;

	close_sock:
	close(fd);

	return -1;
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

int ustcomm_send_request(struct ustcomm_connection *conn, const char *req, char **reply)
{
	int result;

	result = send(conn->fd, req, strlen(req), MSG_NOSIGNAL);
	if(result == -1) {
		if(errno != EPIPE)
			PERROR("send");
		return -1;
	}

	if(!reply)
		return 1;

	*reply = (char *) malloc(MSG_MAX+1);
	result = recv(conn->fd, *reply, MSG_MAX, 0);
	if(result == -1) {
		if(errno != ECONNRESET)
			PERROR("recv");
		return -1;
	}
	else if(result == 0) {
		return 0;
	}
	
	(*reply)[result] = '\0';

	return 1;
}

int ustcomm_connect_path(const char *path, struct ustcomm_connection *conn, pid_t signalpid)
{
	int fd;
	int result;
	struct sockaddr_un addr;

	result = fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if(result == -1) {
		PERROR("socket");
		return -1;
	}

	addr.sun_family = AF_UNIX;

	result = snprintf(addr.sun_path, UNIX_PATH_MAX, "%s", path);
	if(result >= UNIX_PATH_MAX) {
		ERR("string overflow allocating socket name");
		return -1;
	}

	if(signalpid >= 0) {
		result = signal_process(signalpid);
		if(result == -1) {
			ERR("could not signal process");
			return -1;
		}
	}

	result = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	if(result == -1) {
		PERROR("connect");
		return -1;
	}

	conn->fd = fd;

	return 0;
}

int ustcomm_disconnect(struct ustcomm_connection *conn)
{
	return close(conn->fd);
}

int ustcomm_connect_app(pid_t pid, struct ustcomm_connection *conn)
{
	int result;
	char path[UNIX_PATH_MAX];


	result = snprintf(path, UNIX_PATH_MAX, "%s/%d", SOCK_DIR, pid);
	if(result >= UNIX_PATH_MAX) {
		ERR("string overflow allocating socket name");
		return -1;
	}

	return ustcomm_connect_path(path, conn, pid);
}

static int ensure_dir_exists(const char *dir)
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
		char buf[200];
		int result;

		result = snprintf(buf, sizeof(buf), "mkdir -p \"%s\"", dir);
		if(result >= sizeof(buf)) {
			ERR("snprintf buffer overflow");
			return -1;
		}
		result = system(buf);
		if(result != 0) {
			ERR("executing command %s", buf);
			return -1;
		}
	}

	return 0;
}

/* Called by an application to initialize its server so daemons can
 * connect to it.
 */

int ustcomm_init_app(pid_t pid, struct ustcomm_app *handle)
{
	int result;
	char *name;

	result = asprintf(&name, "%s/%d", SOCK_DIR, (int)pid);
	if(result >= UNIX_PATH_MAX) {
		ERR("string overflow allocating socket name");
		return -1;
	}

	result = ensure_dir_exists(SOCK_DIR);
	if(result == -1) {
		ERR("Unable to create socket directory %s", SOCK_DIR);
		return -1;
	}

	handle->server.listen_fd = init_named_socket(name, &(handle->server.socketpath));
	if(handle->server.listen_fd < 0) {
		ERR("Error initializing named socket (%s). Check that directory exists and that it is writable.", name);
		goto free_name;
	}
	free(name);

	INIT_LIST_HEAD(&handle->server.connections);

	return 0;

free_name:
	free(name);
	return -1;
}

/* Used by the daemon to initialize its server so applications
 * can connect to it.
 */

int ustcomm_init_ustd(struct ustcomm_ustd *handle, const char *sock_path)
{
	char *name;
	int retval = 0;

	if(sock_path) {
		asprintf(&name, "%s", sock_path);
	}
	else {
		int result;

		/* Only check if socket dir exists if we are using the default directory */
		result = ensure_dir_exists(SOCK_DIR);
		if(result == -1) {
			ERR("Unable to create socket directory %s", SOCK_DIR);
			return -1;
		}

		asprintf(&name, "%s/%s", SOCK_DIR, "ustd");
	}

	handle->server.listen_fd = init_named_socket(name, &handle->server.socketpath);
	if(handle->server.listen_fd < 0) {
		ERR("error initializing named socket at %s", name);
		retval = -1;
		goto free_name;
	}

	INIT_LIST_HEAD(&handle->server.connections);

free_name:
	free(name);

	return retval;
}

void ustcomm_fini_app(struct ustcomm_app *handle)
{
	int result;
	struct stat st;

	/* Destroy socket */
	result = stat(handle->server.socketpath, &st);
	if(result == -1) {
		PERROR("stat (%s)", handle->server.socketpath);
		return;
	}

	/* Paranoid check before deleting. */
	result = S_ISSOCK(st.st_mode);
	if(!result) {
		ERR("The socket we are about to delete is not a socket.");
		return;
	}

	result = unlink(handle->server.socketpath);
	if(result == -1) {
		PERROR("unlink");
	}
}

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

	asprintf(&retval, "%.*s", (int)(end-start), start);

	return retval;
}

