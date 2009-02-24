#define _GNU_SOURCE
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

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

//static void bt(void)
//{
//	void *buffer[100];
//	int result;
//
//	result = backtrace(&buffer, 100);
//	backtrace_symbols_fd(buffer, result, STDERR_FILENO);
//}

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

int send_message_path(const char *path, const char *msg, char **reply, int signalpid)
{
	int fd;
	int result;
	struct sockaddr_un addr;

	result = fd = socket(PF_UNIX, SOCK_DGRAM, 0);
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

	result = sendto(fd, msg, strlen(msg), 0, (struct sockaddr *)&addr, sizeof(addr));
	if(result == -1) {
		PERROR("sendto");
		return -1;
	}

	if(!reply)
		return 0;

	*reply = (char *) malloc(MSG_MAX+1);
	result = recvfrom(fd, *reply, MSG_MAX, 0, NULL, NULL);
	if(result == -1) {
		PERROR("recvfrom");
		return -1;
	}
	
	(*reply)[result] = '\0';

	return 0;
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

static int recv_message_fd(int fd, char **msg, struct ustcomm_source *src)
{
	int result;
	size_t initial_addrlen,addrlen;

	*msg = (char *) malloc(MSG_MAX+1);

	if(src) {
		initial_addrlen = addrlen = sizeof(src->addr);

		result = recvfrom(fd, *msg, MSG_MAX, 0, &src->addr, &addrlen);
		if(initial_addrlen != addrlen) {
			ERR("recvfrom: unexpected address length");
			return -1;
		}
	}
	else {
		result = recvfrom(fd, *msg, MSG_MAX, 0, NULL, NULL);
	}

	if(result == -1) {
		PERROR("recvfrom");
		return -1;
	}

	(*msg)[result] = '\0';
	
	DBG("ustcomm_app_recv_message: result is %d, message is %s", result, (*msg));

	return 0;
}

int ustcomm_ustd_recv_message(struct ustcomm_ustd *ustd, char **msg, struct ustcomm_source *src)
{
	return recv_message_fd(ustd->fd, msg, src);
}

int ustcomm_app_recv_message(struct ustcomm_app *app, char **msg, struct ustcomm_source *src)
{
	return recv_message_fd(app->fd, msg, src);
}

static int init_named_socket(char *name, char **path_out)
{
	int result;
	int fd;

	struct sockaddr_un addr;
	
	result = fd = socket(PF_UNIX, SOCK_DGRAM, 0);
	if(result == -1) {
		PERROR("socket");
		return -1;
	}

	addr.sun_family = AF_UNIX;

	strncpy(addr.sun_path, name, UNIX_PATH_MAX);
	addr.sun_path[UNIX_PATH_MAX-1] = '\0';

	result = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if(result == -1) {
		PERROR("bind");
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

	handle->fd = init_named_socket(name, &(handle->socketpath));
	if(handle->fd < 0) {
		goto free_name;
	}
	free(name);

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

	handle->fd = init_named_socket(name, &handle->socketpath);
	if(handle->fd < 0)
		return handle->fd;
	free(name);

	return 0;
}

char *find_tok(const char *str)
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

	retval = strndupa(start, end-start);

	return retval;
}

