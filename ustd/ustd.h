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
