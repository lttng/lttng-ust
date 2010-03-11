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
#include "share.h"
#include "multipoll.h"

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

static int mkdir_p(const char *path, mode_t mode)
{
	const char *path_p;
	char *tmp;

	int retval = 0;
	int result;

	tmp = malloc(strlen(path) + 1);
	if (tmp == NULL)
		return -1;

	/* skip first / */
	path_p = path+1;

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
	return retval;
}

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

void ustcomm_init_connection(struct ustcomm_connection *conn)
{
	conn->recv_buf = NULL;
	conn->recv_buf_size = 0;
	conn->recv_buf_alloc = 0;
}

int pid_is_online(pid_t pid) {
	return 1;
}

/* Send a message
 *
 * @fd: file descriptor to send to
 * @msg: a null-terminated string containing the message to send
 *
 * Return value:
 * -1: error
 * 0: connection closed
 * 1: success
 */

static int send_message_fd(int fd, const char *msg)
{
	int result;

	/* Send including the final \0 */
	result = patient_send(fd, msg, strlen(msg)+1, MSG_NOSIGNAL);
	if(result == -1) {
		if(errno != EPIPE)
			PERROR("send");
		return -1;
	}
	else if(result == 0) {
		return 0;
	}

	DBG("sent message \"%s\"", msg);
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
 * returns 0 to indicate no message was received (end of stream)
 * returns -1 to indicate an error
 */

#define RECV_INCREMENT 1000
#define RECV_INITIAL_BUF_SIZE 10

static int recv_message_fd(int fd, char **recv_buf, int *recv_buf_size, int *recv_buf_alloc, char **msg)
{
	int result;

	/* 1. Check if there is a message in the buf */
	/* 2. If not, do:
           2.1 receive chunk and put it in buffer
	   2.2 process full message if there is one
	   -- while no message arrived
	*/

	for(;;) {
		int i;
		int nulfound = 0;

		/* Search for full message in buffer */
		for(i=0; i<*recv_buf_size; i++) {
			if((*recv_buf)[i] == '\0') {
				nulfound = 1;
				break;
			}
		}

		/* Process found message */
		if(nulfound == 1) {
			char *newbuf;

			if(i == 0) {
				/* problem */
				WARN("received empty message");
			}
			*msg = strndup(*recv_buf, i);

			/* Remove processed message from buffer */
			newbuf = (char *) malloc(*recv_buf_size - (i+1));
			memcpy(newbuf, *recv_buf + (i+1), *recv_buf_size - (i+1));
			free(*recv_buf);
			*recv_buf = newbuf;
			*recv_buf_size -= (i+1);
			*recv_buf_alloc -= (i+1);

			return 1;
		}

		/* Receive a chunk from the fd */
		if(*recv_buf_alloc - *recv_buf_size < RECV_INCREMENT) {
			*recv_buf_alloc += RECV_INCREMENT - (*recv_buf_alloc - *recv_buf_size);
			*recv_buf = (char *) realloc(*recv_buf, *recv_buf_alloc);
		}

		result = recv(fd, *recv_buf+*recv_buf_size, RECV_INCREMENT, 0);
		if(result == -1) {
			if(errno == ECONNRESET) {
				*recv_buf_size = 0;
				return 0;
			}
			/* real error */
			PERROR("recv");
			return -1;
		}
		if(result == 0) {
			return 0;
		}
		*recv_buf_size += result;

		/* Go back to the beginning to check if there is a full message in the buffer */
	}

	DBG("received message \"%s\"", *recv_buf);

	return 1;

}

static int recv_message_conn(struct ustcomm_connection *conn, char **msg)
{
	return recv_message_fd(conn->fd, &conn->recv_buf, &conn->recv_buf_size, &conn->recv_buf_alloc, msg);
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
		ustcomm_close_app(conn);
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
	struct ustcomm_connection **conn_table;
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

		conn_table = (struct ustcomm_connection **) malloc(n_fds * sizeof(struct ustcomm_connection *));
		if(conn_table == NULL) {
			ERR("malloc returned NULL");
			retval = -1;
			goto free_fds_return;
		}

		/* special idx 0 is for listening socket */
		fds[idx].fd = server->listen_fd;
		fds[idx].events = POLLIN;
		idx++;

		list_for_each_entry(conn, &server->connections, list) {
			fds[idx].fd = conn->fd;
			fds[idx].events = POLLIN;
			conn_table[idx] = conn;
			idx++;
		}

		while((result = poll(fds, n_fds, timeout)) == -1 && errno == EINTR)
			/* nothing */;
		if(result == -1) {
			PERROR("poll");
			retval = -1;
			goto free_conn_table_return;
		}

		if(result == 0) {
			retval = 0;
			goto free_conn_table_return;
		}

		if(fds[0].revents) {
			struct ustcomm_connection *newconn;
			int newfd;

			result = newfd = accept(server->listen_fd, NULL, NULL);
			if(result == -1) {
				PERROR("accept");
				retval = -1;
				goto free_conn_table_return;
			}

			newconn = (struct ustcomm_connection *) malloc(sizeof(struct ustcomm_connection));
			if(newconn == NULL) {
				ERR("malloc returned NULL");
				return -1;
			}

			ustcomm_init_connection(newconn);
			newconn->fd = newfd;

			list_add(&newconn->list, &server->connections);
		}

		for(idx=1; idx<n_fds; idx++) {
			if(fds[idx].revents) {
				retval = recv_message_conn(conn_table[idx], msg);
				if(src)
					src->fd = fds[idx].fd;

				if(retval == 0) {
					/* connection finished */
					list_for_each_entry(conn, &server->connections, list) {
						if(conn->fd == fds[idx].fd) {
							ustcomm_close_app(conn);
							list_del(&conn->list);
							free(conn);
							break;
						}
					}
				}
				else {
					goto free_conn_table_return;
				}
			}
		}

		free(fds);
		free(conn_table);
	}

free_conn_table_return:
	free(conn_table);
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
		DBG("socket already exists; overwriting");
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

	/* Send including the final \0 */
	result = send_message_fd(conn->fd, req);
	if(result != 1)
		return result;

	if(!reply)
		return 1;

	result = recv_message_conn(conn, reply);
	if(result == -1) {
		return -1;
	}
	else if(result == 0) {
		return 0;
	}
	
	return 1;
}

/* Return value:
 *  0: success
 * -1: error
 */

int ustcomm_connect_path(const char *path, struct ustcomm_connection *conn, pid_t signalpid)
{
	int fd;
	int result;
	struct sockaddr_un addr;

	ustcomm_init_connection(conn);

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
		PERROR("connect (path=%s)", path);
		return -1;
	}

	conn->fd = fd;

	return 0;
}

int ustcomm_disconnect(struct ustcomm_connection *conn)
{
	return close(conn->fd);
}

/* Open a connection to a traceable app.
 *
 * Return value:
 *  0: success
 * -1: error
 */

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

/* Close a connection to a traceable app. It frees the
 * resources. It however does not free the
 * ustcomm_connection itself.
 */

int ustcomm_close_app(struct ustcomm_connection *conn)
{
	close(conn->fd);
	free(conn->recv_buf);

	return 0;
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
		int result;

		result = mkdir_p(dir, 0777);
		if(result != 0) {
			ERR("executing in recursive creation of directory %s", dir);
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

static void ustcomm_fini_server(struct ustcomm_server *server, int keep_socket_file)
{
	int result;
	struct stat st;

	if(!keep_socket_file) {
		/* Destroy socket */
		result = stat(server->socketpath, &st);
		if(result == -1) {
			PERROR("stat (%s)", server->socketpath);
			return;
		}

		/* Paranoid check before deleting. */
		result = S_ISSOCK(st.st_mode);
		if(!result) {
			ERR("The socket we are about to delete is not a socket.");
			return;
		}

		result = unlink(server->socketpath);
		if(result == -1) {
			PERROR("unlink");
		}
	}

	free(server->socketpath);

	result = close(server->listen_fd);
	if(result == -1) {
		PERROR("close");
		return;
	}
}

/* Free a traceable application server */

void ustcomm_fini_app(struct ustcomm_app *handle, int keep_socket_file)
{
	ustcomm_fini_server(&handle->server, keep_socket_file);
}

/* Free a ustd server */

void ustcomm_fini_ustd(struct ustcomm_ustd *handle)
{
	ustcomm_fini_server(&handle->server, 0);
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

/* Callback from multipoll.
 * Receive a new connection on the listening socket.
 */

static int process_mp_incoming_conn(void *priv, int fd, short events)
{
	struct ustcomm_connection *newconn;
	struct ustcomm_server *server = (struct ustcomm_server *) priv;
	int newfd;
	int result;

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

	ustcomm_init_connection(newconn);
	newconn->fd = newfd;

	list_add(&newconn->list, &server->connections);

	return 0;
}

/* Callback from multipoll.
 * Receive a message on an existing connection.
 */

static int process_mp_conn_msg(void *priv, int fd, short revents)
{
	struct ustcomm_multipoll_conn_info *mpinfo = (struct ustcomm_multipoll_conn_info *) priv;
	int result;
	char *msg;
	struct ustcomm_source src;

	if(revents) {
		src.fd = fd;

		result = recv_message_conn(mpinfo->conn, &msg);
		if(result == -1) {
			ERR("error in recv_message_conn");
		}

		else if(result == 0) {
			/* connection finished */
			ustcomm_close_app(mpinfo->conn);
			list_del(&mpinfo->conn->list);
			free(mpinfo->conn);
		}
		else {
			mpinfo->cb(msg, &src);
			free(msg);
		}
	}

	return 0;
}

int free_ustcomm_client_poll(void *data)
{
	free(data);
	return 0;
}

void ustcomm_mp_add_app_clients(struct mpentries *ent, struct ustcomm_app *app, int (*cb)(struct ustcomm_connection *conn, char *msg))
{
	struct ustcomm_connection *conn;

	/* add listener socket */
	multipoll_add(ent, app->server.listen_fd, POLLIN, process_mp_incoming_conn, &app->server, NULL);

	list_for_each_entry(conn, &app->server.connections, list) {
		struct ustcomm_multipoll_conn_info *mpinfo = (struct ustcomm_multipoll_conn_info *) malloc(sizeof(struct ustcomm_multipoll_conn_info));
		mpinfo->conn = conn;
		mpinfo->cb = cb;
		multipoll_add(ent, conn->fd, POLLIN, process_mp_conn_msg, mpinfo, free_ustcomm_client_poll);
	}
}
