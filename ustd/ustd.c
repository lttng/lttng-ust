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

	int shmid;
	void *mem;
	int memlen;

	int n_subbufs;
	int subbuf_size;

	int file_fd; /* output file */

	struct list_head list;

	long consumed_old;
};

/* return value: 0 = subbuffer is finished, it won't produce data anymore
 *               1 = got subbuffer successfully
 *               <0 = error
 */

int get_subbuffer(struct buffer_info *buf)
{
	char *send_msg;
	char *received_msg;
	char *rep_code;
	int retval;
	int result;

	asprintf(&send_msg, "get_subbuffer %s", buf->name);
	result = send_message(buf->pid, send_msg, &received_msg);
	if(result < 0) {
		ERR("get_subbuffer: send_message failed");
		return -1;
	}
	free(send_msg);

	result = sscanf(received_msg, "%as %ld", &rep_code, &buf->consumed_old);
	if(result != 2 && result != 1) {
		ERR("unable to parse response to get_subbuffer");
		return -1;
	}

	DBG("received msg is %s", received_msg);

	if(!strcmp(rep_code, "OK")) {
		DBG("got subbuffer %s", buf->name);
		retval = 1;
	}
	else if(nth_token_is(received_msg, "END", 0) == 1) {
		return 0;
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
	result = send_message(buf->pid, send_msg, &received_msg);
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

void *consumer_thread(void *arg)
{
	struct buffer_info *buf = (struct buffer_info *) arg;
	int result;

	for(;;) {
		result = get_subbuffer(buf);
		if(result == -1) {
			ERR("error getting subbuffer");
			continue;
		}
		if(result == 0) {
			/* this is done */
			break;
		}

		/* write data to file */
		result = patient_write(buf->file_fd, buf->mem + (buf->consumed_old & (buf->n_subbufs * buf->subbuf_size-1)), buf->subbuf_size);
		if(result == -1) {
			PERROR("write");
			/* FIXME: maybe drop this trace */
		}

		result = put_subbuffer(buf);
		if(result == -1) {
			ERR("error putting subbuffer");
			break;
		}
	}

	DBG("thread for buffer %s is stopping", buf->name);

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

	/* get shmid */
	asprintf(&send_msg, "get_shmid %s", buf->name);
	send_message(pid, send_msg, &received_msg);
	free(send_msg);
	DBG("got buffer name %s", buf->name);

	result = sscanf(received_msg, "%d", &buf->shmid);
	if(result != 1) {
		ERR("unable to parse response to get_shmid");
		return -1;
	}
	free(received_msg);
	DBG("got shmid %d", buf->shmid);

	/* get n_subbufs */
	asprintf(&send_msg, "get_n_subbufs %s", buf->name);
	send_message(pid, send_msg, &received_msg);
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
	send_message(pid, send_msg, &received_msg);
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
	DBG("successfully attached memory");

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
