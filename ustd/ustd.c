#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/shm.h>

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
};

int add_buffer(pid_t pid, char *bufname)
{
	struct buffer_info *buf;
	char *send_msg;
	char *received_msg;
	int result;

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

	for(;;) {
		char *recvbuf;

		ustcomm_ustd_recv_message(&ustd, &recvbuf, NULL);

		if(!strncmp(recvbuf, "collect", 7)) {
			pid_t pid;
			char *bufname;
			int result;

			result = sscanf(recvbuf, "%*s %d %50as", &pid, &bufname);
			if(result != 2) {
				fprintf(stderr, "parsing error: %s\n", recvbuf);
			}

			add_buffer(pid, bufname);
			
		}

		free(recvbuf);
	}

	return 0;
}
