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

#include <ust/ustconsumer.h>
#include "lowlevel.h"
#include "usterr.h"
#include "ustcomm.h"

#define GET_SUBBUF_OK 1
#define GET_SUBBUF_DONE 0
#define GET_SUBBUF_DIED 2

#define PUT_SUBBUF_OK 1
#define PUT_SUBBUF_DIED 0
#define PUT_SUBBUF_PUSHED 2
#define PUT_SUBBUF_DONE 3

#define UNIX_PATH_MAX 108

static int get_subbuffer(struct buffer_info *buf)
{
	struct ustcomm_header _send_hdr, *send_hdr;
	struct ustcomm_header _recv_hdr, *recv_hdr;
	struct ustcomm_buffer_info _send_msg, _recv_msg;
	struct ustcomm_buffer_info *send_msg, *recv_msg;
	int result;

	send_hdr = &_send_hdr;
	recv_hdr = &_recv_hdr;
	send_msg = &_send_msg;
	recv_msg = &_recv_msg;

	result = ustcomm_pack_buffer_info(send_hdr, send_msg, buf->trace,
					  buf->channel, buf->channel_cpu);
	if (result < 0) {
		return result;
	}

	send_hdr->command = GET_SUBBUFFER;

	result = ustcomm_req(buf->app_sock, send_hdr, (char *)send_msg,
			     recv_hdr, (char *)recv_msg);
	if ((result < 0 && (errno == ECONNRESET || errno == EPIPE)) ||
	    result == 0) {
		DBG("app died while being traced");
		return GET_SUBBUF_DIED;
	} else if (result < 0) {
		ERR("get_subbuffer: ustcomm_req failed");
		return result;
	}

	if (!recv_hdr->result) {
		DBG("got subbuffer %s", buf->name);
		buf->consumed_old = recv_msg->consumed_old;
		return GET_SUBBUF_OK;
	} else if (recv_hdr->result == -ENODATA) {
		DBG("For buffer %s, the trace was not found. This likely means"
		    " it was destroyed by the user.", buf->name);
		return GET_SUBBUF_DIED;
	}

	DBG("error getting subbuffer %s", buf->name);
	return recv_hdr->result;
}

static int put_subbuffer(struct buffer_info *buf)
{
	struct ustcomm_header _send_hdr, *send_hdr;
	struct ustcomm_header _recv_hdr, *recv_hdr;
	struct ustcomm_buffer_info _send_msg, *send_msg;
	int result;

	send_hdr = &_send_hdr;
	recv_hdr = &_recv_hdr;
	send_msg = &_send_msg;

	result = ustcomm_pack_buffer_info(send_hdr, send_msg, buf->trace,
					  buf->channel, buf->channel_cpu);
	if (result < 0) {
		return result;
	}

	send_hdr->command = PUT_SUBBUFFER;
	send_msg->consumed_old = buf->consumed_old;

	result = ustcomm_req(buf->app_sock, send_hdr, (char *)send_msg,
			     recv_hdr, NULL);
	if ((result < 0 && (errno == ECONNRESET || errno == EPIPE)) ||
	    result == 0) {
		DBG("app died while being traced");
		return PUT_SUBBUF_DIED;
	} else if (result < 0) {
		ERR("put_subbuffer: ustcomm_req failed");
		return result;
	}

	if (!recv_hdr->result) {
		DBG("put subbuffer %s", buf->name);
		return PUT_SUBBUF_OK;
	} else if (recv_hdr->result == -ENODATA) {
		DBG("For buffer %s, the trace was not found. This likely means"
		    " it was destroyed by the user.", buf->name);
		return PUT_SUBBUF_DIED;
	}

	DBG("error getting subbuffer %s", buf->name);
	return recv_hdr->result;
}

void decrement_active_buffers(void *arg)
{
	struct ustconsumer_instance *instance = arg;
	pthread_mutex_lock(&instance->mutex);
	instance->active_buffers--;
	pthread_mutex_unlock(&instance->mutex);
}

static int get_pidunique(int sock, s64 *pidunique)
{
	struct ustcomm_header _send_hdr, *send_hdr;
	struct ustcomm_header _recv_hdr, *recv_hdr;
	struct ustcomm_pidunique _recv_msg, *recv_msg;
	int result;

	send_hdr = &_send_hdr;
	recv_hdr = &_recv_hdr;
	recv_msg = &_recv_msg;

	memset(send_hdr, 0, sizeof(*send_hdr));

	send_hdr->command = GET_PIDUNIQUE;
	result = ustcomm_req(sock, send_hdr, NULL, recv_hdr, (char *)recv_msg);
	if (result < 1) {
		return -ENOTCONN;
	}
	if (recv_hdr->result < 0) {
		ERR("App responded with error: %s", strerror(recv_hdr->result));
		return recv_hdr->result;
	}

	*pidunique = recv_msg->pidunique;

	return 0;
}

static int get_buf_shmid_pipe_fd(int sock, struct buffer_info *buf,
				 int *buf_shmid, int *buf_struct_shmid,
				 int *buf_pipe_fd)
{
	struct ustcomm_header _send_hdr, *send_hdr;
	struct ustcomm_header _recv_hdr, *recv_hdr;
	struct ustcomm_buffer_info _send_msg, *send_msg;
	struct ustcomm_buffer_info _recv_msg, *recv_msg;
	int result, recv_pipe_fd;

	send_hdr = &_send_hdr;
	recv_hdr = &_recv_hdr;
	send_msg = &_send_msg;
	recv_msg = &_recv_msg;

	result = ustcomm_pack_buffer_info(send_hdr, send_msg, buf->trace,
					  buf->channel, buf->channel_cpu);
	if (result < 0) {
		ERR("Failed to pack buffer info");
		return result;
	}

	send_hdr->command = GET_BUF_SHMID_PIPE_FD;

	result = ustcomm_send(sock, send_hdr, (char *)send_msg);
	if (result < 1) {
		ERR("Failed to send request");
		return -ENOTCONN;
	}
	result = ustcomm_recv_fd(sock, recv_hdr, (char *)recv_msg, &recv_pipe_fd);
	if (result < 1) {
		ERR("Failed to receive message and fd");
		return -ENOTCONN;
	}
	if (recv_hdr->result < 0) {
		ERR("App responded with error %s", strerror(recv_hdr->result));
		return recv_hdr->result;
	}

	*buf_shmid = recv_msg->buf_shmid;
	*buf_struct_shmid = recv_msg->buf_struct_shmid;
	*buf_pipe_fd = recv_pipe_fd;

	return 0;
}

static int get_subbuf_num_size(int sock, struct buffer_info *buf,
			       int *subbuf_num, int *subbuf_size)
{
	struct ustcomm_header _send_hdr, *send_hdr;
	struct ustcomm_header _recv_hdr, *recv_hdr;
	struct ustcomm_channel_info _send_msg, *send_msg;
	struct ustcomm_channel_info _recv_msg, *recv_msg;
	int result;

	send_hdr = &_send_hdr;
	recv_hdr = &_recv_hdr;
	send_msg = &_send_msg;
	recv_msg = &_recv_msg;

	result = ustcomm_pack_channel_info(send_hdr, send_msg, buf->trace,
					   buf->channel);
	if (result < 0) {
		return result;
	}

	send_hdr->command = GET_SUBBUF_NUM_SIZE;

	result = ustcomm_req(sock, send_hdr, (char *)send_msg,
			     recv_hdr, (char *)recv_msg);
	if (result < 1) {
		return -ENOTCONN;
	}

	*subbuf_num = recv_msg->subbuf_num;
	*subbuf_size = recv_msg->subbuf_size;

	return recv_hdr->result;
}


static int notify_buffer_mapped(int sock, struct buffer_info *buf)
{
	struct ustcomm_header _send_hdr, *send_hdr;
	struct ustcomm_header _recv_hdr, *recv_hdr;
	struct ustcomm_buffer_info _send_msg, *send_msg;
	int result;

	send_hdr = &_send_hdr;
	recv_hdr = &_recv_hdr;
	send_msg = &_send_msg;

	result = ustcomm_pack_buffer_info(send_hdr, send_msg, buf->trace,
					  buf->channel, buf->channel_cpu);
	if (result < 0) {
		return result;
	}

	send_hdr->command = NOTIFY_BUF_MAPPED;

	result = ustcomm_req(sock, send_hdr, (char *)send_msg,
			     recv_hdr, NULL);
	if (result < 1) {
		return -ENOTCONN;
	}

	return recv_hdr->result;
}


struct buffer_info *connect_buffer(struct ustconsumer_instance *instance, pid_t pid,
				   const char *trace, const char *channel,
				   int channel_cpu)
{
	struct buffer_info *buf;
	int result;
	struct shmid_ds shmds;

	buf = (struct buffer_info *) zmalloc(sizeof(struct buffer_info));
	if(buf == NULL) {
		ERR("add_buffer: insufficient memory");
		return NULL;
	}

	buf->trace = strdup(trace);
	if (!buf->trace) {
		goto free_buf;
	}

	buf->channel = strdup(channel);
	if (!buf->channel) {
		goto free_buf_trace;
	}

	result = asprintf(&buf->name, "%s_%d", channel, channel_cpu);
	if (result < 0 || buf->name == NULL) {
		goto free_buf_channel;
	}

	buf->channel_cpu = channel_cpu;
	buf->pid = pid;

	result = ustcomm_connect_app(buf->pid, &buf->app_sock);
	if(result) {
		WARN("unable to connect to process, it probably died before we were able to connect");
		goto free_buf_name;
	}

	/* get pidunique */
	result = get_pidunique(buf->app_sock, &buf->pidunique);
	if (result < 0) {
		ERR("Failed to get pidunique");
		goto close_app_sock;
	}

	/* get shmid and pipe fd */
	result = get_buf_shmid_pipe_fd(buf->app_sock, buf, &buf->shmid,
				       &buf->bufstruct_shmid, &buf->pipe_fd);
	if (result < 0) {
		ERR("Failed to get buf_shmid and pipe_fd");
		goto close_app_sock;
	} else {
		struct stat temp;
		fstat(buf->pipe_fd, &temp);
		if (!S_ISFIFO(temp.st_mode)) {
			ERR("Didn't receive a fifo from the app");
			goto close_app_sock;
		}
	}


	/* get number of subbufs and subbuf size */
	result = get_subbuf_num_size(buf->app_sock, buf, &buf->n_subbufs,
				     &buf->subbuf_size);
	if (result < 0) {
		ERR("Failed to get subbuf number and size");
		goto close_fifo;
	}

	/* attach memory */
	buf->mem = shmat(buf->shmid, NULL, 0);
	if(buf->mem == (void *) 0) {
		PERROR("shmat");
		goto close_fifo;
	}
	DBG("successfully attached buffer memory");

	buf->bufstruct_mem = shmat(buf->bufstruct_shmid, NULL, 0);
	if(buf->bufstruct_mem == (void *) 0) {
		PERROR("shmat");
		goto shmdt_mem;
	}
	DBG("successfully attached buffer bufstruct memory");

	/* obtain info on the memory segment */
	result = shmctl(buf->shmid, IPC_STAT, &shmds);
	if(result == -1) {
		PERROR("shmctl");
		goto shmdt_bufstruct_mem;
	}
	buf->memlen = shmds.shm_segsz;

	/* Notify the application that we have mapped the buffer */
	result = notify_buffer_mapped(buf->app_sock, buf);
	if (result < 0) {
		goto shmdt_bufstruct_mem;
	}

	if(instance->callbacks->on_open_buffer)
		instance->callbacks->on_open_buffer(instance->callbacks, buf);

	pthread_mutex_lock(&instance->mutex);
	instance->active_buffers++;
	pthread_mutex_unlock(&instance->mutex);

	return buf;

shmdt_bufstruct_mem:
	shmdt(buf->bufstruct_mem);

shmdt_mem:
	shmdt(buf->mem);

close_fifo:
	close(buf->pipe_fd);

close_app_sock:
	close(buf->app_sock);

free_buf_name:
	free(buf->name);

free_buf_channel:
	free(buf->channel);

free_buf_trace:
	free(buf->trace);

free_buf:
	free(buf);
	return NULL;
}

static void destroy_buffer(struct ustconsumer_callbacks *callbacks,
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

int consumer_loop(struct ustconsumer_instance *instance, struct buffer_info *buf)
{
	int result = 0;
	int read_result;
	char read_buf;

	pthread_cleanup_push(decrement_active_buffers, instance);

	for(;;) {
		read_result = read(buf->pipe_fd, &read_buf, 1);
		/* get the subbuffer */
		if (read_result == 1) {
			result = get_subbuffer(buf);
			if (result < 0) {
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
			/* TODO: check on_put_error return value */
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
	const char *trace;
	const char *channel;
	int channel_cpu;
	struct ustconsumer_instance *instance;
};

void *consumer_thread(void *arg)
{
	struct buffer_info *buf;
	struct consumer_thread_args *args = (struct consumer_thread_args *) arg;
	int result;
	sigset_t sigset;

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

	buf = connect_buffer(args->instance, args->pid, args->trace,
			     args->channel, args->channel_cpu);
	if(buf == NULL) {
		ERR("failed to connect to buffer");
		goto end;
	}

	consumer_loop(args->instance, buf);

	destroy_buffer(args->instance->callbacks, buf);

	end:

	if(args->instance->callbacks->on_close_thread)
		args->instance->callbacks->on_close_thread(args->instance->callbacks);

	free((void *)args->channel);
	free(args);
	return NULL;
}

int start_consuming_buffer(struct ustconsumer_instance *instance, pid_t pid,
			   const char *trace, const char *channel,
			   int channel_cpu)
{
	pthread_t thr;
	struct consumer_thread_args *args;
	int result;

	DBG("beginning of start_consuming_buffer: args: pid %d bufname %s_%d", pid, channel,
	    channel_cpu);

	args = (struct consumer_thread_args *) zmalloc(sizeof(struct consumer_thread_args));
	if (!args) {
		return -ENOMEM;
	}

	args->pid = pid;
	args->trace = strdup(trace);
	args->channel = strdup(channel);
	args->channel_cpu = channel_cpu;
	args->instance = instance;
	DBG("beginning2 of start_consuming_buffer: args: pid %d trace %s"
	    " bufname %s_%d", args->pid, args->trace, args->channel, args->channel_cpu);

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
	DBG("end of start_consuming_buffer: args: pid %d trace %s "
	    "bufname %s_%d", args->pid, args->channel, args->trace, args->channel_cpu);

	return 0;
}
static void process_client_cmd(int sock, struct ustcomm_header *req_header,
			       char *recvbuf, struct ustconsumer_instance *instance)
{
	int result;
	struct ustcomm_header _res_header;
	struct ustcomm_header *res_header = &_res_header;
	struct ustcomm_buffer_info *buf_inf;

	DBG("Processing client command");

	switch (req_header->command) {
	case CONSUME_BUFFER:

		buf_inf = (struct ustcomm_buffer_info *)recvbuf;
		result = ustcomm_unpack_buffer_info(buf_inf);
		if (result < 0) {
			ERR("Couldn't unpack buffer info");
			return;
		}

		DBG("Going to consume trace %s buffer %s_%d in process %d",
		    buf_inf->trace, buf_inf->channel, buf_inf->ch_cpu,
		    buf_inf->pid);
		result = start_consuming_buffer(instance, buf_inf->pid,
						buf_inf->trace,
						buf_inf->channel,
						buf_inf->ch_cpu);
		if (result < 0) {
			ERR("error in add_buffer");
			return;
		}

		res_header->result = 0;
		break;
	case EXIT:
		res_header->result = 0;
		/* Only there to force poll to return */
		break;
	default:
		res_header->result = -EINVAL;
		WARN("unknown command: %d", req_header->command);
	}

	if (ustcomm_send(sock, res_header, NULL) <= 0) {
		ERR("couldn't send command response");
	}
}

#define MAX_EVENTS 10

int ustconsumer_start_instance(struct ustconsumer_instance *instance)
{
	struct ustcomm_header recv_hdr;
	char recv_buf[USTCOMM_BUFFER_SIZE];
	struct ustcomm_sock *epoll_sock;
	struct epoll_event events[MAX_EVENTS];
	struct sockaddr addr;
	int result, epoll_fd, accept_fd, nfds, i, addr_size, timeout;

	if(!instance->is_init) {
		ERR("libustconsumer instance not initialized");
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
			PERROR("ustconsumer_start_instance: epoll_wait failed");
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
					PERROR("ustconsumer_start_instance: "
					       "accept failed");
					continue;
				}
				ustcomm_init_sock(accept_fd, epoll_fd,
						 &instance->connections);
			} else {
				result = ustcomm_recv(epoll_sock->fd, &recv_hdr,
						      recv_buf);
				if (result < 1) {
					ustcomm_del_sock(epoll_sock, 0);
				} else {
					process_client_cmd(epoll_sock->fd,
							   &recv_hdr, recv_buf,
							   instance);
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

	ustconsumer_delete_instance(instance);

	return 0;
}

/* FIXME: threads and connections !? */
void ustconsumer_delete_instance(struct ustconsumer_instance *instance)
{
	if (instance->is_init) {
		ustcomm_del_named_sock(instance->listen_sock, 0);
		close(instance->epoll_fd);
	}

	pthread_mutex_destroy(&instance->mutex);
	free(instance->sock_path);
	free(instance);
}

/* FIXME: Do something about the fixed path length, maybe get rid
 * of the whole concept and use a pipe?
 */
int ustconsumer_stop_instance(struct ustconsumer_instance *instance, int send_msg)
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

struct ustconsumer_instance
*ustconsumer_new_instance(struct ustconsumer_callbacks *callbacks,
		      char *sock_path)
{
	struct ustconsumer_instance *instance =
		zmalloc(sizeof(struct ustconsumer_instance));
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

static int init_ustconsumer_socket(struct ustconsumer_instance *instance)
{
	char *name;

	if (instance->sock_path) {
		if (asprintf(&name, "%s", instance->sock_path) < 0) {
			ERR("ustcomm_init_ustconsumer : asprintf failed (sock_path %s)",
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

		if (asprintf(&name, "%s/%s", SOCK_DIR, "ustconsumer") < 0) {
			ERR("ustcomm_init_ustconsumer : asprintf failed (%s/ustconsumer)",
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

	CDS_INIT_LIST_HEAD(&instance->connections);

	free(name);

	return 0;

close_epoll:
	close(instance->epoll_fd);
free_name:
	free(name);

	return -1;
}

int ustconsumer_init_instance(struct ustconsumer_instance *instance)
{
	int result;
	result = init_ustconsumer_socket(instance);
	if(result == -1) {
		ERR("failed to initialize socket");
		return 1;
	}
	instance->is_init = 1;
	return 0;
}

