#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/shm.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "localerr.h"
#include "ustcomm.h"

struct buffer_info {
	char *name;
	pid_t pid;

	int shmid;
	void *mem;
	int memlen;

	int nsubbufs;
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

	result = sscanf(received_msg, "%d", &buf->shmid);
	if(result != 1) {
		ERR("unable to parse response to get_shmid");
		return -1;
	}
	free(received_msg);

	/* get nsubbufs */
	asprintf(&send_msg, "get_n_subbufs %s", buf->name);
	send_message(pid, send_msg, &received_msg);
	free(send_msg);

	result = sscanf(received_msg, "%d", &buf->nsubbufs);
	if(result != 1) {
		ERR("unable to parse response to get_shmid");
		return -1;
	}
	free(received_msg);

	/* attach memory */
	buf->mem = shmat(buf->shmid, NULL, 0);
	if(buf->mem == (void *) 0) {
		perror("shmat");
		return -1;
	}

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
