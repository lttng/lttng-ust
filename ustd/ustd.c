/*
 * Copyright (C) 2009  Pierre-Marc Fournier
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/shm.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "localerr.h"
#include "ustcomm.h"

struct list_head buffers = LIST_HEAD_INIT(buffers);

struct buffer_info {
	char *name;
	pid_t pid;
	struct ustcomm_connection conn;

	int shmid;
	int bufstruct_shmid;

	/* the buffer memory */
	void *mem;
	/* buffer size */
	int memlen;
	/* number of subbuffers in buffer */
	int n_subbufs;
	/* size of each subbuffer */
	int subbuf_size;

	/* the buffer information struct */
	void *bufstruct_mem;

	int file_fd; /* output file */

	struct list_head list;

	long consumed_old;
};

/* return value: 0 = subbuffer is finished, it won't produce data anymore
 *               1 = got subbuffer successfully
 *               <0 = error
 */

#define GET_SUBBUF_OK 1
#define GET_SUBBUF_DONE 0
#define GET_SUBBUF_DIED 2

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
	if(result < 0) {
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
		retval = 1;
	}
	else {
		ERR("invalid response to put_subbuffer");
	}

	free(rep_code);
	return retval;
}

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

int get_subbuffer_died(struct buffer_info *buf)
{
	return 0;
}

//int ltt_do_get_subbuf(struct rchan_buf *buf, struct ltt_channel_buf_struct *ltt_buf, long *pconsumed_old)
//{
//	struct ltt_channel_buf_struct *ltt_buf = buf->bufstruct_mem;
//
////ust//	struct ltt_channel_struct *ltt_channel = (struct ltt_channel_struct *)buf->chan->private_data;
//	long consumed_old, consumed_idx, commit_count, write_offset;
//	consumed_old = atomic_long_read(&ltt_buf->consumed);
//	consumed_idx = SUBBUF_INDEX(consumed_old, buf->chan);
//	commit_count = local_read(&ltt_buf->commit_count[consumed_idx]);
//	/*
//	 * Make sure we read the commit count before reading the buffer
//	 * data and the write offset. Correct consumed offset ordering
//	 * wrt commit count is insured by the use of cmpxchg to update
//	 * the consumed offset.
//	 */
//	smp_rmb();
//	write_offset = local_read(&ltt_buf->offset);
//	/*
//	 * Check that the subbuffer we are trying to consume has been
//	 * already fully committed.
//	 */
//	if (((commit_count - buf->chan->subbuf_size)
//	     & ltt_channel->commit_count_mask)
//	    - (BUFFER_TRUNC(consumed_old, buf->chan)
//	       >> ltt_channel->n_subbufs_order)
//	    != 0) {
//		return -EAGAIN;
//	}
//	/*
//	 * Check that we are not about to read the same subbuffer in
//	 * which the writer head is.
//	 */
//	if ((SUBBUF_TRUNC(write_offset, buf->chan)
//	   - SUBBUF_TRUNC(consumed_old, buf->chan))
//	   == 0) {
//		return -EAGAIN;
//	}
//
//	*pconsumed_old = consumed_old;
//	return 0;
//}

void *consumer_thread(void *arg)
{
	struct buffer_info *buf = (struct buffer_info *) arg;
	int result;
	int died = 0;

	for(;;) {
		/* get the subbuffer */
		if(died == 0) {
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
				died = 1;
			}
		}
		if(died == 1) {
			result = get_subbuffer_died(buf);
			if(result <= 0) {
				break;
			}
		}

		/* write data to file */
		result = patient_write(buf->file_fd, buf->mem + (buf->consumed_old & (buf->n_subbufs * buf->subbuf_size-1)), buf->subbuf_size);
		if(result == -1) {
			PERROR("write");
			/* FIXME: maybe drop this trace */
		}

		/* put the subbuffer */
		if(died == 0) {
			result = put_subbuffer(buf);
			if(result == -1) {
				ERR("error putting subbuffer");
				break;
			}
		}
		else {
//			result = put_subbuffer_died(buf);
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
		ERR("unable to connect to process");
		return -1;
	}

	/* get shmid */
	asprintf(&send_msg, "get_shmid %s", buf->name);
	ustcomm_send_request(&buf->conn, send_msg, &received_msg);
	free(send_msg);
	DBG("got buffer name %s", buf->name);

	result = sscanf(received_msg, "%d %d", &buf->shmid, &buf->bufstruct_shmid);
	if(result != 2) {
		ERR("unable to parse response to get_shmid");
		return -1;
	}
	free(received_msg);
	DBG("got shmids %d %d", buf->shmid, buf->bufstruct_shmid);

	/* get n_subbufs */
	asprintf(&send_msg, "get_n_subbufs %s", buf->name);
	ustcomm_send_request(&buf->conn, send_msg, &received_msg);
	free(send_msg);

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

	/* open file for output */
	asprintf(&tmp, "/tmp/trace/%s_0", buf->name);
	result = fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 00600);
	if(result == -1) {
		PERROR("open");
		return -1;
	}
	buf->file_fd = fd;
	free(tmp);

	//list_add(&buf->list, &buffers);

	pthread_create(&thr, NULL, consumer_thread, buf);

	return 0;
}

int main(int argc, char **argv)
{
	struct ustcomm_ustd ustd;
	int result;

	result = ustcomm_init_ustd(&ustd);
	if(result == -1) {
		ERR("failed to initialize socket");
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
