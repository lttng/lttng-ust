#ifndef USTD_H
#define USTD_H

#include "ustcomm.h"

#define USTD_DEFAULT_TRACE_PATH "/tmp/usttrace"

struct buffer_info {
	const char *name;
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

	s64 pidunique;

	/* the offset we must truncate to, to unput the last subbuffer */
	off_t previous_offset;
};

void finish_consuming_dead_subbuffer(struct buffer_info *buf);
size_t subbuffer_data_size(void *subbuf);

#endif /* USTD_H */
