#define _GNU_SOURCE
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <poll.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <execinfo.h>

#include "ustcomm.h"
#include "localerr.h"

#define UNIX_PATH_MAX 108
#define SOCK_DIR "/tmp/socks"
#define UST_SIGNAL SIGIO

#define MSG_MAX 1000

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

static void signal_process(pid_t pid)
{
	int result;

	result = kill(pid, UST_SIGNAL);
	if(result == -1) {
		PERROR("kill");
		return;
	}

	sleep(1);
}

int send_message_fd(int fd, const char *msg, char **reply)
{
	int result;

	result = send(fd, msg, strlen(msg), 0);
	if(result == -1) {
		PERROR("send");
		return -1;
	}
	else if(result == 0) {
		return 0;
	}

	if(!reply)
		return 1;

	*reply = (char *) malloc(MSG_MAX+1);
	result = recv(fd, *reply, MSG_MAX, 0);
	if(result == -1) {
		PERROR("recv");
		return -1;
	}
	else if(result == 0) {
		return 0;
	}
	
	(*reply)[result] = '\0';

	return 1;
}

int send_message_path(const char *path, const char *msg, char **reply, int signalpid)
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

	if(signalpid >= 0)
		signal_process(signalpid);

	result = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	if(result == -1) {
		PERROR("connect");
		return -1;
	}

	return send_message_fd(fd, msg, reply);
}

/* pid: the pid of the trace process that must receive the msg
   msg: pointer to a null-terminated message to send
   reply: location where to put the null-terminated string of the reply;
	  it must be free'd after usage
 */

int send_message(pid_t pid, const char *msg, char **reply)
{
	int result;
	char path[UNIX_PATH_MAX];

	result = snprintf(path, UNIX_PATH_MAX, "%s/%d", SOCK_DIR, pid);
	if(result >= UNIX_PATH_MAX) {
		fprintf(stderr, "string overflow allocating socket name");
		return -1;
	}

	send_message_path(path, msg, reply, pid);

	return 0;
}

/* Called by an app to ask the consumer daemon to connect to it. */

int ustcomm_request_consumer(pid_t pid, const char *channel)
{
	char path[UNIX_PATH_MAX];
	int result;
	char *msg;

	result = snprintf(path, UNIX_PATH_MAX, "%s/ustd", SOCK_DIR);
	if(result >= UNIX_PATH_MAX) {
		fprintf(stderr, "string overflow allocating socket name");
		return -1;
	}

	asprintf(&msg, "collect %d %s", pid, channel); 

	send_message_path(path, msg, NULL, -1);
	free(msg);

	return 0;
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

	result = send_message_fd(src->fd, msg, NULL);
	if(result) {
		ERR("error in send_message_fd");
		return -1;
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

		result = poll(fds, n_fds, timeout);
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

static int init_named_socket(char *name, char **path_out)
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
		*path_out = "";
		*path_out = strdupa(addr.sun_path);
	}

	return fd;

	close_sock:
	close(fd);

	return -1;
}

int ustcomm_init_app(pid_t pid, struct ustcomm_app *handle)
{
	int result;
	char *name;

	result = asprintf(&name, "%s/%d", SOCK_DIR, (int)pid);
	if(result >= UNIX_PATH_MAX) {
		ERR("string overflow allocating socket name");
		return -1;
	}

	handle->server.listen_fd = init_named_socket(name, &(handle->server.socketpath));
	if(handle->server.listen_fd < 0) {
		ERR("error initializing named socket");
		goto free_name;
	}
	free(name);

	INIT_LIST_HEAD(&handle->server.connections);

	return 0;

free_name:
	free(name);
	return -1;
}

int ustcomm_init_ustd(struct ustcomm_ustd *handle)
{
	int result;
	char *name;

	result = asprintf(&name, "%s/%s", SOCK_DIR, "ustd");
	if(result >= UNIX_PATH_MAX) {
		ERR("string overflow allocating socket name");
		return -1;
	}

	handle->server.listen_fd = init_named_socket(name, &handle->server.socketpath);
	if(handle->server.listen_fd < 0) {
		ERR("error initializing named socket");
		goto free_name;
	}
	free(name);

	INIT_LIST_HEAD(&handle->server.connections);

	return 0;

free_name:
	free(name);
	return -1;
}

static char *find_tok(char *str)
{
	while(*str == ' ') {
		str++;

		if(*str == 0)
			return NULL;
	}

	return str;
}

static char *find_sep(char *str)
{
	while(*str != ' ') {
		str++;

		if(*str == 0)
			break;
	}

	return str;
}

int nth_token_is(char *str, char *token, int tok_no)
{
	int i;
	char *start;
	char *end;

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

char *nth_token(char *str, int tok_no)
{
	static char *retval = NULL;
	int i;
	char *start;
	char *end;

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

