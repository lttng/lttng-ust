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

#ifndef USTCOMM_H
#define USTCOMM_H

#include <sys/types.h>
#include <sys/un.h>
#include <urcu/list.h>

#include <ust/kcompat/kcompat.h>

#define SOCK_DIR "/tmp/ust-app-socks"

struct ustcomm_sock {
	struct cds_list_head list;
	int fd;
	int epoll_fd;
};

struct ustcomm_header {
	int command;
	long size;
	int result;
	int fd_included;
};

#define USTCOMM_BUFFER_SIZE ((1 << 12) - sizeof(struct ustcomm_header))

/* Specify a sata size that leaves margin at the end of a buffer
 * in order to make sure that we never have more data than
 * will fit in the buffer AND that the last chars (due to a
 * pre-receive memset) will always be 0, terminating any string
 */
#define USTCOMM_DATA_SIZE (USTCOMM_BUFFER_SIZE - 20 * sizeof(void *))

enum tracectl_commands {
	ALLOC_TRACE,
	CONSUME_BUFFER,
	CREATE_TRACE,
	DESTROY_TRACE,
	DISABLE_MARKER,
	ENABLE_MARKER,
	EXIT,
	FORCE_SUBBUF_SWITCH,
	GET_BUF_SHMID_PIPE_FD,
	GET_PIDUNIQUE,
	GET_SOCK_PATH,
	GET_SUBBUFFER,
	GET_SUBBUF_NUM_SIZE,
	LIST_MARKERS,
	LIST_TRACE_EVENTS,
	LOAD_PROBE_LIB,
	NOTIFY_BUF_MAPPED,
	PRINT_MARKERS,
	PRINT_TRACE_EVENTS,
	PUT_SUBBUFFER,
	SETUP_TRACE,
	SET_SOCK_PATH,
	SET_SUBBUF_NUM,
	SET_SUBBUF_SIZE,
	START,
	START_TRACE,
	STOP_TRACE,
};

struct ustcomm_single_field {
	char *field;
	char data[USTCOMM_DATA_SIZE];
};

struct ustcomm_channel_info {
	char *trace;
	char *channel;
	unsigned int subbuf_size;
	unsigned int subbuf_num;
	char data[USTCOMM_DATA_SIZE];
};

struct ustcomm_buffer_info {
	char *trace;
	char *channel;
	int ch_cpu;
	pid_t pid;
	int buf_shmid;
	int buf_struct_shmid;
	long consumed_old;
	char data[USTCOMM_DATA_SIZE];
};

struct ustcomm_marker_info {
	char *trace;
	char *channel;
	char *marker;
	char data[USTCOMM_DATA_SIZE];
};

struct ustcomm_pidunique {
	s64 pidunique;
};

struct ustcomm_notify_buf_mapped {
	char data[USTCOMM_DATA_SIZE];
};

/* Ensure directory existence, usefull for unix sockets */
extern int ensure_dir_exists(const char *dir);

/* Create and delete sockets */
extern struct ustcomm_sock * ustcomm_init_sock(int fd, int epoll_fd,
					       struct cds_list_head *list);
extern void ustcomm_del_sock(struct ustcomm_sock *sock, int keep_in_epoll);

/* Create and delete named sockets */
extern struct ustcomm_sock * ustcomm_init_named_socket(const char *name,
						       int epoll_fd);
extern void ustcomm_del_named_sock(struct ustcomm_sock *sock,
				   int keep_socket_file);

/* Send and receive functions for file descriptors */
extern int ustcomm_send_fd(int sock, const struct ustcomm_header *header,
			   const char *data, int *fd);
extern int ustcomm_recv_fd(int sock, struct ustcomm_header *header,
			   char *data, int *fd);

/* Normal send and receive functions */
extern int ustcomm_send(int sock, const struct ustcomm_header *header,
			const char *data);
extern int ustcomm_recv(int sock, struct ustcomm_header *header,
			char *data);

/* Receive and allocate data, not to be used inside libust */
extern int ustcomm_recv_alloc(int sock,
			      struct ustcomm_header *header,
			      char **data);

/* Request function, send and receive */
extern int ustcomm_req(int sock,
		       const struct ustcomm_header *req_header,
		       const char *req_data,
		       struct ustcomm_header *res_header,
		       char *res_data);

extern int ustcomm_request_consumer(pid_t pid, const char *channel);
extern int ustcomm_connect_app(pid_t pid, int *app_fd);
extern int ustcomm_connect_path(const char *path, int *connection_fd);

extern int nth_token_is(const char *str, const char *token, int tok_no);

extern char *nth_token(const char *str, int tok_no);

/* String serialising functions, printf straight into a buffer */
#define USTCOMM_POISON_PTR (void *)0x19831018

extern char * ustcomm_print_data(char *data_field, int field_size,
				 int *offset, const char *format, ...);
extern char * ustcomm_restore_ptr(char *ptr, char *data_field,
				  int data_field_size);

#define COMPUTE_MSG_SIZE(struct_ptr, offset)				\
	(size_t) (long)(struct_ptr)->data - (long)(struct_ptr) + (offset)

/* Packing and unpacking functions, making life easier */
extern int ustcomm_pack_single_field(struct ustcomm_header *header,
				   struct ustcomm_single_field *sf,
				   const char *trace);

extern int ustcomm_unpack_single_field(struct ustcomm_single_field *sf);

extern int ustcomm_pack_channel_info(struct ustcomm_header *header,
				     struct ustcomm_channel_info *ch_inf,
				     const char *trace,
				     const char *channel);

extern int ustcomm_unpack_channel_info(struct ustcomm_channel_info *ch_inf);

extern int ustcomm_pack_buffer_info(struct ustcomm_header *header,
				    struct ustcomm_buffer_info *buf_inf,
				    const char *trace,
				    const char *channel,
				    int channel_cpu);

extern int ustcomm_unpack_buffer_info(struct ustcomm_buffer_info *buf_inf);

extern int ustcomm_pack_marker_info(struct ustcomm_header *header,
				    struct ustcomm_marker_info *marker_inf,
				    const char *trace,
				    const char *channel,
				    const char *marker);

extern int ustcomm_unpack_marker_info(struct ustcomm_marker_info *marker_inf);

#endif /* USTCOMM_H */
