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
#include <sys/shm.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "ustd.h"
#include "localerr.h"
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

int test_sigpipe(void)
{
	sigset_t sigset;
	int result;

	result = sigemptyset(&sigset);
	if(result == -1) {
		perror("sigemptyset");
		return -1;
	}
	result = sigaddset(&sigset, SIGPIPE);
	if(result == -1) {
		perror("sigaddset");
		return -1;
	}

	result = sigtimedwait(&sigset, NULL, &(struct timespec){0,0});
	if(result == -1 && errno == EAGAIN) {
		/* no signal received */
		return 0;
	}
	else if(result == -1) {
		perror("sigtimedwait");
		return -1;
	}
	else if(result == SIGPIPE) {
		/* received sigpipe */
		return 1;
	}
	else {
		assert(0);
	}
}

int get_subbuffer(struct buffer_info *buf)
{
	char *send_msg;
	char *received_msg;
	char *rep_code;
	int retval;
	int result;

	asprintf(&send_msg, "get_subbuffer %s", buf->name);
	result = ustcomm_send_request(&buf->conn, send_msg, &received_msg);
	free(send_msg);
	if(test_sigpipe()) {
		WARN("process %d destroyed before we could connect to it", buf->pid);
		return GET_SUBBUF_DONE;
	}
	else if(result < 0) {
		ERR("get_subbuffer: ustcomm_send_request failed");
		return -1;
	}
	else if(result == 0) {
		DBG("app died while being traced");
		return GET_SUBBUF_DIED;
	}

	result = sscanf(received_msg, "%as %ld", &rep_code, &buf->consumed_old);
	if(result != 2 && result != 1) {
		ERR("unable to parse response to get_subbuffer");
		return -1;
	}

	DBG("received msg is %s", received_msg);

	if(!strcmp(rep_code, "OK")) {
		DBG("got subbuffer %s", buf->name);
		retval = GET_SUBBUF_OK;
	}
	else if(nth_token_is(received_msg, "END", 0) == 1) {
		return GET_SUBBUF_DONE;
	}
	else {
		DBG("error getting subbuffer %s", buf->name);
		retval = -1;
	}

	/* FIMXE: free correctly the stuff */
	free(received_msg);
	free(rep_code);
	return retval;
}

int put_subbuffer(struct buffer_info *buf)
{
	char *send_msg;
	char *received_msg;
	char *rep_code;
	int retval;
	int result;

	asprintf(&send_msg, "put_subbuffer %s %ld", buf->name, buf->consumed_old);
	result = ustcomm_send_request(&buf->conn, send_msg, &received_msg);
	if(result < 0) {
		ERR("put_subbuffer: send_message failed");
		return -1;
	}
	free(send_msg);

	result = sscanf(received_msg, "%as", &rep_code);
	if(result != 1) {
		ERR("unable to parse response to put_subbuffer");
		return -1;
	}
	free(received_msg);

	if(!strcmp(rep_code, "OK")) {
		DBG("subbuffer put %s", buf->name);
		retval = PUT_SUBBUF_OK;
	}
	else {
		DBG("put_subbuffer: received error, we were pushed");
		return PUT_SUBBUF_PUSHED;
	}

	free(rep_code);
	return retval;
}

/* This write is patient because it restarts if it was incomplete.
 */

ssize_t patient_write(int fd, const void *buf, size_t count)
{
	const char *bufc = (const char *) buf;
	int result;

	for(;;) {
		result = write(fd, bufc, count);
		if(result <= 0) {
			return result;
		}
		count -= result;
		bufc += result;

		if(count == 0) {
			break;
		}
	}

	return bufc-(const char *)buf;
}

void *consumer_thread(void *arg)
{
	struct buffer_info *buf = (struct buffer_info *) arg;
	int result;

	for(;;) {
		/* get the subbuffer */
		result = get_subbuffer(buf);
		if(result == -1) {
			ERR("error getting subbuffer");
			continue;
		}
		else if(result == GET_SUBBUF_DONE) {
			/* this is done */
			break;
		}
		else if(result == GET_SUBBUF_DIED) {
			finish_consuming_dead_subbuffer(buf);
			break;
		}

		/* write data to file */
		result = patient_write(buf->file_fd, buf->mem + (buf->consumed_old & (buf->n_subbufs * buf->subbuf_size-1)), buf->subbuf_size);
		if(result == -1) {
			PERROR("write");
			/* FIXME: maybe drop this trace */
		}

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
			WARN("application died while putting subbuffer");
			/* FIXME: probably need to skip the first subbuffer in finish_consuming_dead_subbuffer */
			finish_consuming_dead_subbuffer(buf);
		}
		else if(result == PUT_SUBBUF_OK) {
		}
	}

	DBG("thread for buffer %s is stopping", buf->name);

	/* FIXME: destroy, unalloc... */

	return NULL;
}

int add_buffer(pid_t pid, char *bufname)
{
	struct buffer_info *buf;
	char *send_msg;
	char *received_msg;
	int result;
	char *tmp;
	int fd;
	pthread_t thr;
	struct shmid_ds shmds;

	buf = (struct buffer_info *) malloc(sizeof(struct buffer_info));
	if(buf == NULL) {
		ERR("add_buffer: insufficient memory");
		return -1;
	}

	buf->name = bufname;
	buf->pid = pid;

	/* connect to app */
	result = ustcomm_connect_app(buf->pid, &buf->conn);
	if(result) {
		WARN("unable to connect to process, it probably died before we were able to connect");
		return -1;
	}

	/* get shmid */
	asprintf(&send_msg, "get_shmid %s", buf->name);
	result = ustcomm_send_request(&buf->conn, send_msg, &received_msg);
	free(send_msg);
	if(result == -1) {
		ERR("problem in ustcomm_send_request(get_shmid)");
		return -1;
	}

	result = sscanf(received_msg, "%d %d", &buf->shmid, &buf->bufstruct_shmid);
	if(result != 2) {
		ERR("unable to parse response to get_shmid");
		return -1;
	}
	free(received_msg);
	DBG("got shmids %d %d", buf->shmid, buf->bufstruct_shmid);

	/* get n_subbufs */
	asprintf(&send_msg, "get_n_subbufs %s", buf->name);
	result = ustcomm_send_request(&buf->conn, send_msg, &received_msg);
	free(send_msg);
	if(result == -1) {
		ERR("problem in ustcomm_send_request(g_n_subbufs)");
		return -1;
	}

	result = sscanf(received_msg, "%d", &buf->n_subbufs);
	if(result != 1) {
		ERR("unable to parse response to get_n_subbufs");
		return -1;
	}
	free(received_msg);
	DBG("got n_subbufs %d", buf->n_subbufs);

	/* get subbuf size */
	asprintf(&send_msg, "get_subbuf_size %s", buf->name);
	ustcomm_send_request(&buf->conn, send_msg, &received_msg);
	free(send_msg);

	result = sscanf(received_msg, "%d", &buf->subbuf_size);
	if(result != 1) {
		ERR("unable to parse response to get_subbuf_size");
		return -1;
	}
	free(received_msg);
	DBG("got subbuf_size %d", buf->subbuf_size);

	/* attach memory */
	buf->mem = shmat(buf->shmid, NULL, 0);
	if(buf->mem == (void *) 0) {
		perror("shmat");
		return -1;
	}
	DBG("successfully attached buffer memory");

	buf->bufstruct_mem = shmat(buf->bufstruct_shmid, NULL, 0);
	if(buf->bufstruct_mem == (void *) 0) {
		perror("shmat");
		return -1;
	}
	DBG("successfully attached buffer bufstruct memory");

	/* obtain info on the memory segment */
	result = shmctl(buf->shmid, IPC_STAT, &shmds);
	if(result == -1) {
		perror("shmctl");
		return -1;
	}
	buf->memlen = shmds.shm_segsz;

	/* open file for output */
	asprintf(&tmp, "/tmp/trace/%s_0", buf->name);
	result = fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 00600);
	if(result == -1) {
		PERROR("open");
		ERR("failed opening trace file %s", tmp);
		return -1;
	}
	buf->file_fd = fd;
	free(tmp);

	pthread_create(&thr, NULL, consumer_thread, buf);

	return 0;
}

int main(int argc, char **argv)
{
	struct ustcomm_ustd ustd;
	int result;
	sigset_t sigset;

	result = ustcomm_init_ustd(&ustd);
	if(result == -1) {
		ERR("failed to initialize socket");
		return 1;
	}

	result = sigemptyset(&sigset);
	if(result == -1) {
		perror("sigemptyset");
		return 1;
	}
	result = sigaddset(&sigset, SIGPIPE);
	if(result == -1) {
		perror("sigaddset");
		return 1;
	}
	result = sigprocmask(SIG_BLOCK, &sigset, NULL);
	if(result == -1) {
		perror("sigprocmask");
		return 1;
	}

	/* app loop */
	for(;;) {
		char *recvbuf;

		/* check for requests on our public socket */
		result = ustcomm_ustd_recv_message(&ustd, &recvbuf, NULL, 100);
		if(result == -1) {
			ERR("error in ustcomm_ustd_recv_message");
			continue;
		}
		if(result > 0) {
			if(!strncmp(recvbuf, "collect", 7)) {
				pid_t pid;
				char *bufname;
				int result;

				result = sscanf(recvbuf, "%*s %d %50as", &pid, &bufname);
				if(result != 2) {
					fprintf(stderr, "parsing error: %s\n", recvbuf);
				}

				result = add_buffer(pid, bufname);
				if(result < 0) {
					ERR("error in add_buffer");
					continue;
				}
			}

			free(recvbuf);
		}
	}

	return 0;
}
