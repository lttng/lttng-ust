#ifndef USTD_H
#define USTD_H

#include "ustcomm.h"

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

	long consumed_old;
};

ssize_t patient_write(int fd, const void *buf, size_t count);

void finish_consuming_dead_subbuffer(struct buffer_info *buf);

#endif /* USTD_H */
