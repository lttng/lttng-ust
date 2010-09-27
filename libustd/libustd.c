/* Copyright (C) 2009  Pierre-Marc Fournier
 *               2010  Alexis Halle
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

#include <sys/epoll.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include <ust/ustd.h>
#include "lowlevel.h"
#include "usterr.h"
#include "ustcomm.h"

/* return value: 0 = subbuffer is finished, it won't produce data anymore
 *               1 = got subbuffer successfully
 *               <0 = error
 */

#define GET_SUBBUF_OK 1
#define GET_SUBBUF_DONE 0
#define GET_SUBBUF_DIED 2

#define PUT_SUBBUF_OK 1
#define PUT_SUBBUF_DIED 0
#define PUT_SUBBUF_PUSHED 2
#define PUT_SUBBUF_DONE 3

#define UNIX_PATH_MAX 108

int get_subbuffer(struct buffer_info *buf)
{
	char *send_msg=NULL;
	char *received_msg=NULL;
	char *rep_code=NULL;
	int retval;
	int result;

	if (asprintf(&send_msg, "get_subbuffer %s", buf->name) < 0) {
		ERR("get_subbuffer : asprintf failed (%s)",
		    buf->name);
		retval = -1;
		goto end;
	}

	result = ustcomm_send_request(buf->app_sock, send_msg, &received_msg);
	if((result == -1 && (errno == ECONNRESET || errno == EPIPE)) || result == 0) {
		DBG("app died while being traced");
		retval = GET_SUBBUF_DIED;
		goto end;
	}
	else if(result < 0) {
		ERR("get_subbuffer: ustcomm_send_request failed");
		retval = -1;
		goto end;
	}

	result = sscanf(received_msg, "%as %ld", &rep_code, &buf->consumed_old);
	if(result != 2 && result != 1) {
		ERR("unable to parse response to get_subbuffer");
		retval = -1;
		free(received_msg);
		goto end_rep;
	}

	if (!strcmp(rep_code, "OK")) {
		DBG("got subbuffer %s", buf->name);
		retval = GET_SUBBUF_OK;
	} else if(!strcmp(received_msg, "NOTFOUND")) {
		DBG("For buffer %s, the trace was not found. This likely means it was destroyed by the user.", buf->name);
		retval = GET_SUBBUF_DIED;
		goto end_rep;
	} else {
		DBG("error getting subbuffer %s", buf->name);
		retval = -1;
	}

	/* FIXME: free correctly the stuff */
end_rep:
	if(rep_code)
		free(rep_code);
end:
	if(send_msg)
		free(send_msg);
	if(received_msg)
		free(received_msg);

	return retval;
}

int put_subbuffer(struct buffer_info *buf)
{
	char *send_msg=NULL;
	char *received_msg=NULL;
	char *rep_code=NULL;
	int retval;
	int result;

	if (asprintf(&send_msg, "put_subbuffer %s %ld", buf->name, buf->consumed_old) < 0) {
		ERR("put_subbuffer : asprintf failed (%s %ld)",
		    buf->name, buf->consumed_old);
		retval = -1;
		goto end;
	}
	result = ustcomm_send_request(buf->app_sock, send_msg, &received_msg);
	if(result < 0 && (errno == ECONNRESET || errno == EPIPE)) {
		retval = PUT_SUBBUF_DIED;
		goto end;
	}
	else if(result < 0) {
		ERR("put_subbuffer: send_message failed");
		retval = -1;
		goto end;
	}
	else if(result == 0) {
		/* Program seems finished. However this might not be
		 * the last subbuffer that has to be collected.
		 */
		retval = PUT_SUBBUF_DIED;
		goto end;
	}

	result = sscanf(received_msg, "%as", &rep_code);
	if(result != 1) {
		ERR("unable to parse response to put_subbuffer");
		retval = -1;
		goto end_rep;
	}

	if(!strcmp(rep_code, "OK")) {
		DBG("subbuffer put %s", buf->name);
		retval = PUT_SUBBUF_OK;
	}
	else if(!strcmp(received_msg, "NOTFOUND")) {
		DBG("For buffer %s, the trace was not found. This likely means it was destroyed by the user.", buf->name);
		/* However, maybe this was not the last subbuffer. So
		 * we return the program died.
		 */
		retval = PUT_SUBBUF_DIED;
		goto end_rep;
	}
	else {
		DBG("put_subbuffer: received error, we were pushed");
		retval = PUT_SUBBUF_PUSHED;
		goto end_rep;
	}

end_rep:
	if(rep_code)
		free(rep_code);

end:
	if(send_msg)
		free(send_msg);
	if(received_msg)
		free(received_msg);

	return retval;
}

void decrement_active_buffers(void *arg)
{
	struct libustd_instance *instance = arg;
	pthread_mutex_lock(&instance->mutex);
	instance->active_buffers--;
	pthread_mutex_unlock(&instance->mutex);
}

struct buffer_info *connect_buffer(struct libustd_instance *instance, pid_t pid, const char *bufname)
{
	struct buffer_info *buf;
	char *send_msg;
	char *received_msg;
	int result;
	struct shmid_ds shmds;
	struct ustcomm_header header;

	buf = (struct buffer_info *) zmalloc(sizeof(struct buffer_info));
	if(buf == NULL) {
		ERR("add_buffer: insufficient memory");
		return NULL;
	}

	buf->name = bufname;
	buf->pid = pid;

	/* FIXME: Fix all the freeing and exit sequence from this functions */
	/* connect to app */
	result = ustcomm_connect_app(buf->pid, &buf->app_sock);
	if(result) {
		WARN("unable to connect to process, it probably died before we were able to connect");
		return NULL;
	}

	/* get pidunique */
	if (asprintf(&send_msg, "get_pidunique") < 0) {
		ERR("connect_buffer : asprintf failed (get_pidunique)");
		return NULL;
	}
	result = ustcomm_send_request(buf->app_sock, send_msg, &received_msg);
	free(send_msg);
	if(result == -1) {
		ERR("problem in ustcomm_send_request(get_pidunique)");
		return NULL;
	}
	if(result == 0) {
		goto error;
	}

	result = sscanf(received_msg, "%lld", &buf->pidunique);
	if(result != 1) {
		ERR("unable to parse response to get_pidunique");
		return NULL;
	}
	free(received_msg);
	DBG("got pidunique %lld", buf->pidunique);

	/* get shmid */
	if (asprintf(&send_msg, "get_shmid %s", buf->name) < 0) {
		ERR("connect_buffer : asprintf failed (get_schmid %s)",
		    buf->name);
		return NULL;
	}
	result = ustcomm_send_request(buf->app_sock, send_msg, &received_msg);
	free(send_msg);
	if(result == -1) {
		ERR("problem in ustcomm_send_request(get_shmid)");
		return NULL;
	}
	if(result == 0) {
		goto error;
	}

	result = sscanf(received_msg, "%d %d", &buf->shmid, &buf->bufstruct_shmid);
	if(result != 2) {
		ERR("unable to parse response to get_shmid (\"%s\")", received_msg);
		return NULL;
	}
	free(received_msg);
	DBG("got shmids %d %d", buf->shmid, buf->bufstruct_shmid);

	/* get n_subbufs */
	if (asprintf(&send_msg, "get_n_subbufs %s", buf->name) < 0) {
		ERR("connect_buffer : asprintf failed (get_n_subbufs %s)",
		    buf->name);
		return NULL;
	}
	result = ustcomm_send_request(buf->app_sock, send_msg, &received_msg);
	free(send_msg);
	if(result == -1) {
		ERR("problem in ustcomm_send_request(g_n_subbufs)");
		return NULL;
	}
	if(result == 0) {
		goto error;
	}

	result = sscanf(received_msg, "%d", &buf->n_subbufs);
	if(result != 1) {
		ERR("unable to parse response to get_n_subbufs");
		return NULL;
	}
	free(received_msg);
	DBG("got n_subbufs %d", buf->n_subbufs);

	/* get subbuf size */
	if (asprintf(&send_msg, "get_subbuf_size %s", buf->name) < 0) {
		ERR("connect_buffer : asprintf failed (get_subbuf_size %s)",
		    buf->name);
		return NULL;
	}
	result = ustcomm_send_request(buf->app_sock, send_msg, &received_msg);
	free(send_msg);
	if(result == -1) {
		ERR("problem in ustcomm_send_request(get_subbuf_size)");
		return NULL;
	}
	if(result == 0) {
		goto error;
	}

	result = sscanf(received_msg, "%d", &buf->subbuf_size);
	if(result != 1) {
		ERR("unable to parse response to get_subbuf_size");
		return NULL;
	}
	free(received_msg);
	DBG("got subbuf_size %d", buf->subbuf_size);

	/* attach memory */
	buf->mem = shmat(buf->shmid, NULL, 0);
	if(buf->mem == (void *) 0) {
		PERROR("shmat");
		return NULL;
	}
	DBG("successfully attached buffer memory");

	buf->bufstruct_mem = shmat(buf->bufstruct_shmid, NULL, 0);
	if(buf->bufstruct_mem == (void *) 0) {
		PERROR("shmat");
		return NULL;
	}
	DBG("successfully attached buffer bufstruct memory");

	/* obtain info on the memory segment */
	result = shmctl(buf->shmid, IPC_STAT, &shmds);
	if(result == -1) {
		PERROR("shmctl");
		return NULL;
	}
	buf->memlen = shmds.shm_segsz;

	/* get buffer pipe fd */
	memset(&header, 0, sizeof(header));
	if (asprintf(&send_msg, "get_buffer_fd %s", buf->name) < 0) {
		ERR("connect_buffer : asprintf failed (get_buffer_fd %s)",
		    buf->name);
		return NULL;
	}
	header.size = strlen(send_msg) + 1;
	result = ustcomm_send(buf->app_sock, &header, send_msg);
	free(send_msg);
	if (result <= 0) {
		ERR("ustcomm_send failed.");
		return NULL;
	}
	result = ustcomm_recv_fd(buf->app_sock, &header, NULL, &buf->pipe_fd);
	if (result <= 0) {
		ERR("ustcomm_recv_fd failed");
		return NULL;
	} else {
		struct stat temp;
		fstat(buf->pipe_fd, &temp);
		if (!S_ISFIFO(temp.st_mode)) {
			ERR("Didn't receive a fifo from the app");
			return NULL;
		}
	}
	if(instance->callbacks->on_open_buffer)
		instance->callbacks->on_open_buffer(instance->callbacks, buf);

	pthread_mutex_lock(&instance->mutex);
	instance->active_buffers++;
	pthread_mutex_unlock(&instance->mutex);

	return buf;

error:
	free(buf);
	return NULL;
}

static void destroy_buffer(struct libustd_callbacks *callbacks,
			struct buffer_info *buf)
{
	int result;

	result = close(buf->app_sock);
	if(result == -1) {
		WARN("problem calling ustcomm_close_app");
	}

	result = shmdt(buf->mem);
	if(result == -1) {
		PERROR("shmdt");
	}

	result = shmdt(buf->bufstruct_mem);
	if(result == -1) {
		PERROR("shmdt");
	}

	if(callbacks->on_close_buffer)
		callbacks->on_close_buffer(callbacks, buf);

	free(buf);
}

int consumer_loop(struct libustd_instance *instance, struct buffer_info *buf)
{
	int result, read_result;
	char read_buf;

	pthread_cleanup_push(decrement_active_buffers, instance);

	for(;;) {
		read_result = read(buf->pipe_fd, &read_buf, 1);
		/* get the subbuffer */
		if (read_result == 1) {
			result = get_subbuffer(buf);
			if(result == -1) {
				ERR("error getting subbuffer");
				continue;
			} else if (result == GET_SUBBUF_DIED) {
				finish_consuming_dead_subbuffer(instance->callbacks, buf);
				break;
			}
		} else if ((read_result == -1 && (errno == ECONNRESET || errno == EPIPE)) ||
			   result == 0) {
			DBG("App died while being traced");
			finish_consuming_dead_subbuffer(instance->callbacks, buf);
			break;
		}

		if(instance->callbacks->on_read_subbuffer)
			instance->callbacks->on_read_subbuffer(instance->callbacks, buf);

		/* put the subbuffer */
		result = put_subbuffer(buf);
		if(result == -1) {
			ERR("unknown error putting subbuffer (channel=%s)", buf->name);
			break;
		}
		else if(result == PUT_SUBBUF_PUSHED) {
			ERR("Buffer overflow (channel=%s), reader pushed. This channel will not be usable passed this point.", buf->name);
			break;
		}
		else if(result == PUT_SUBBUF_DIED) {
			DBG("application died while putting subbuffer");
			/* Skip the first subbuffer. We are not sure it is trustable
			 * because the put_subbuffer() did not complete.
			 */
			if(instance->callbacks->on_put_error)
				instance->callbacks->on_put_error(instance->callbacks, buf);

			finish_consuming_dead_subbuffer(instance->callbacks, buf);
			break;
		}
		else if(result == PUT_SUBBUF_DONE) {
			/* Done with this subbuffer */
			/* FIXME: add a case where this branch is used? Upon
			 * normal trace termination, at put_subbuf time, a
			 * special last-subbuffer code could be returned by
			 * the listener.
			 */
			break;
		}
		else if(result == PUT_SUBBUF_OK) {
		}
	}

	DBG("thread for buffer %s is stopping", buf->name);

	/* FIXME: destroy, unalloc... */

	pthread_cleanup_pop(1);

	return 0;
}

struct consumer_thread_args {
	pid_t pid;
	const char *bufname;
	struct libustd_instance *instance;
};

void *consumer_thread(void *arg)
{
	struct buffer_info *buf;
	struct consumer_thread_args *args = (struct consumer_thread_args *) arg;
	int result;
	sigset_t sigset;

	DBG("GOT ARGS: pid %d bufname %s", args->pid, args->bufname);

	if(args->instance->callbacks->on_new_thread)
		args->instance->callbacks->on_new_thread(args->instance->callbacks);

	/* Block signals that should be handled by the main thread. */
	result = sigemptyset(&sigset);
	if(result == -1) {
		PERROR("sigemptyset");
		goto end;
	}
	result = sigaddset(&sigset, SIGTERM);
	if(result == -1) {
		PERROR("sigaddset");
		goto end;
	}
	result = sigaddset(&sigset, SIGINT);
	if(result == -1) {
		PERROR("sigaddset");
		goto end;
	}
	result = sigprocmask(SIG_BLOCK, &sigset, NULL);
	if(result == -1) {
		PERROR("sigprocmask");
		goto end;
	}

	buf = connect_buffer(args->instance, args->pid, args->bufname);
	if(buf == NULL) {
		ERR("failed to connect to buffer");
		goto end;
	}

	consumer_loop(args->instance, buf);

	destroy_buffer(args->instance->callbacks, buf);

	end:

	if(args->instance->callbacks->on_close_thread)
		args->instance->callbacks->on_close_thread(args->instance->callbacks);

	free((void *)args->bufname);
	free(args);
	return NULL;
}

int start_consuming_buffer(
	struct libustd_instance *instance, pid_t pid, const char *bufname)
{
	pthread_t thr;
	struct consumer_thread_args *args;
	int result;

	DBG("beginning of start_consuming_buffer: args: pid %d bufname %s", pid, bufname);

	args = (struct consumer_thread_args *) zmalloc(sizeof(struct consumer_thread_args));

	args->pid = pid;
	args->bufname = strdup(bufname);
	args->instance = instance;
	DBG("beginning2 of start_consuming_buffer: args: pid %d bufname %s", args->pid, args->bufname);

	result = pthread_create(&thr, NULL, consumer_thread, args);
	if(result == -1) {
		ERR("pthread_create failed");
		return -1;
	}
	result = pthread_detach(thr);
	if(result == -1) {
		ERR("pthread_detach failed");
		return -1;
	}
	DBG("end of start_consuming_buffer: args: pid %d bufname %s", args->pid, args->bufname);

	return 0;
}
static void process_client_cmd(char *recvbuf, struct libustd_instance *instance)
{
	if(!strncmp(recvbuf, "collect", 7)) {
		pid_t pid;
		char *bufname = NULL;
		int result;

		result = sscanf(recvbuf, "%*s %d %50as", &pid, &bufname);
		if (result != 2) {
			ERR("parsing error: %s", recvbuf);
			goto free_bufname;
		}

		result = start_consuming_buffer(instance, pid, bufname);
		if (result < 0) {
			ERR("error in add_buffer");
			goto free_bufname;
		}

	free_bufname:
		if (bufname) {
			free(bufname);
		}
	} else if(!strncmp(recvbuf, "exit", 4)) {
		/* Only there to force poll to return */
	} else {
		WARN("unknown command: %s", recvbuf);
	}
}

#define MAX_EVENTS 10

int libustd_start_instance(struct libustd_instance *instance)
{
	struct ustcomm_sock *epoll_sock;
	struct epoll_event events[MAX_EVENTS];
	struct sockaddr addr;
	int result, epoll_fd, accept_fd, nfds, i, addr_size, timeout;

	if(!instance->is_init) {
		ERR("libustd instance not initialized");
		return 1;
	}
	epoll_fd = instance->epoll_fd;

	timeout = -1;

	/* app loop */
	for(;;) {
		nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, timeout);
		if (nfds == -1 && errno == EINTR) {
			/* Caught signal */
		} else if (nfds == -1) {
			PERROR("libustd_start_instance: epoll_wait failed");
			continue;
		}

		for (i = 0; i < nfds; ++i) {
			epoll_sock = (struct ustcomm_sock *)events[i].data.ptr;
			if (epoll_sock == instance->listen_sock) {
				addr_size = sizeof(struct sockaddr);
				accept_fd = accept(epoll_sock->fd,
						   &addr,
						   (socklen_t *)&addr_size);
				if (accept_fd == -1) {
					PERROR("libustd_start_instance: "
					       "accept failed");
					continue;
				}
				ustcomm_init_sock(accept_fd, epoll_fd,
						 &instance->connections);
			} else {
				char *msg = NULL;
				result = recv_message_conn(epoll_sock->fd, &msg);
				if (result == 0) {
					ustcomm_del_sock(epoll_sock, 0);
				} else if (msg) {
					process_client_cmd(msg, instance);
					free(msg);
				}

			}
		}

		if (instance->quit_program) {
			pthread_mutex_lock(&instance->mutex);
			if(instance->active_buffers == 0) {
				pthread_mutex_unlock(&instance->mutex);
				break;
			}
			pthread_mutex_unlock(&instance->mutex);
			timeout = 100;
		}
	}

	if(instance->callbacks->on_trace_end)
		instance->callbacks->on_trace_end(instance);

	libustd_delete_instance(instance);

	return 0;
}

/* FIXME: threads and connections !? */
void libustd_delete_instance(struct libustd_instance *instance)
{
	if (instance->is_init) {
		ustcomm_del_named_sock(instance->listen_sock, 0);
		close(instance->epoll_fd);
	}

	pthread_mutex_destroy(&instance->mutex);
	free(instance->sock_path);
	free(instance);
}

int libustd_stop_instance(struct libustd_instance *instance, int send_msg)
{
	int result;
	int fd;
	int bytes = 0;

	char msg[] = "exit";

	instance->quit_program = 1;

	if(!send_msg)
		return 0;

	/* Send a message through the socket to force poll to return */

	struct sockaddr_un addr;

	result = fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if(result == -1) {
		PERROR("socket");
		return 1;
	}

	addr.sun_family = AF_UNIX;

	strncpy(addr.sun_path, instance->sock_path, UNIX_PATH_MAX);
	addr.sun_path[UNIX_PATH_MAX-1] = '\0';

	result = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	if(result == -1) {
		PERROR("connect");
	}

	while(bytes != sizeof(msg))
		bytes += send(fd, msg, sizeof(msg), 0);

	close(fd);

	return 0;
}

struct libustd_instance
*libustd_new_instance(struct libustd_callbacks *callbacks,
		      char *sock_path)
{
	struct libustd_instance *instance =
		zmalloc(sizeof(struct libustd_instance));
	if(!instance) {
		return NULL;
	}

	instance->callbacks = callbacks;
	instance->quit_program = 0;
	instance->is_init = 0;
	instance->active_buffers = 0;
	pthread_mutex_init(&instance->mutex, NULL);

	if (sock_path) {
		instance->sock_path = strdup(sock_path);
	} else {
		instance->sock_path = NULL;
	}

	return instance;
}

static int init_ustd_socket(struct libustd_instance *instance)
{
	char *name;

	if (instance->sock_path) {
		if (asprintf(&name, "%s", instance->sock_path) < 0) {
			ERR("ustcomm_init_ustd : asprintf failed (sock_path %s)",
			    instance->sock_path);
			return -1;
		}
	} else {
		int result;

		/* Only check if socket dir exists if we are using the default directory */
		result = ensure_dir_exists(SOCK_DIR);
		if (result == -1) {
			ERR("Unable to create socket directory %s", SOCK_DIR);
			return -1;
		}

		if (asprintf(&name, "%s/%s", SOCK_DIR, "ustd") < 0) {
			ERR("ustcomm_init_ustd : asprintf failed (%s/ustd)",
			    SOCK_DIR);
			return -1;
		}
	}

	/* Set up epoll */
	instance->epoll_fd = epoll_create(MAX_EVENTS);
	if (instance->epoll_fd == -1) {
		ERR("epoll_create failed, start instance bailing");
		goto free_name;
	}

	/* Create the named socket */
	instance->listen_sock = ustcomm_init_named_socket(name,
							  instance->epoll_fd);
	if(!instance->listen_sock) {
		ERR("error initializing named socket at %s", name);
		goto close_epoll;
	}

	INIT_LIST_HEAD(&instance->connections);

	free(name);

	return 0;

close_epoll:
	close(instance->epoll_fd);
free_name:
	free(name);

	return -1;
}

int libustd_init_instance(struct libustd_instance *instance)
{
	int result;
	result = init_ustd_socket(instance);
	if(result == -1) {
		ERR("failed to initialize socket");
		return 1;
	}
	instance->is_init = 1;
	return 0;
}

