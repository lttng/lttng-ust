/*
 * libustd header file
 *
 * Copyright 2005-2010 -
 * 		 Mathieu Desnoyers <mathieu.desnoyers@polymtl.ca>
 * Copyright 2010-
 *		 Oumarou Dicko <oumarou.dicko@polymtl.ca>
 *		 Michael Sills-Lavoie <michael.sills-lavoie@polymtl.ca>
 *		 Alexis Halle <alexis.halle@polymtl.ca>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef USTD_H
#define USTD_H

#include <pthread.h>
#include <dirent.h>
#include <ust/kcompat/kcompat.h>
#include <urcu/list.h>

#define USTD_DEFAULT_TRACE_PATH "/tmp/usttrace"

struct ustcomm_sock;

struct buffer_info {
	char *name;
	char *trace;
	char *channel;
	int channel_cpu;

	pid_t pid;
	int app_sock;
	/* The pipe file descriptor */
	int pipe_fd;

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

	long consumed_old;

	s64 pidunique;

	void *user_data;
};

struct libustd_callbacks;

/**
 * struct libustd_instance - Contains the data associated with a trace instance.
 * The lib user can read but MUST NOT change any attributes but callbacks.
 * @callbacks: Contains the necessary callbacks for a tracing session.
 */
struct libustd_instance {
	struct libustd_callbacks *callbacks;
	int quit_program;
	int is_init;
	struct cds_list_head connections;
	int epoll_fd;
	struct ustcomm_sock *listen_sock;
	char *sock_path;
	pthread_mutex_t mutex;
	int active_buffers;
};

/**
* struct libustd_callbacks - Contains the necessary callbacks for a tracing
* session. The user can set the unnecessary functions to NULL if he does not
* need them.
*/
struct libustd_callbacks {
	/**
	 * on_open_buffer - Is called after a buffer is attached to process memory
	 *
	 * @data: pointer to the callbacks structure that has been passed to the
	 *        library.
	 * @buf: structure that contains the data associated with the buffer
	 *
	 * Returns 0 if the callback succeeds else not 0.
	 *
	 * It has to be thread safe, because it is called by many threads.
	 */
	int (*on_open_buffer)(struct libustd_callbacks *data,
				struct buffer_info *buf);

	/**
	 * on_close_buffer - Is called after a buffer is detached from process memory
	 *
	 * @data: pointer to the callbacks structure that has been passed to the
	 *        library.
	 * @buf: structure that contains the data associated with the buffer
	 *
	 * Returns 0 if the callback succeeds else not 0.
	 *
	 * It has to be thread safe, because it is called by many threads.
	 */
	int (*on_close_buffer)(struct libustd_callbacks *data,
				struct buffer_info *buf);

	/**
	 * on_read_subbuffer - Is called after a subbuffer is a reserved.
	 *
	 * @data: pointer to the callbacks structure that has been passed to the
	 *        library.
	 * @buf: structure that contains the data associated with the buffer
	 *
	 * Returns 0 if the callback succeeds else not 0.
	 *
	 * It has to be thread safe, because it is called by many threads.
	 */
	int (*on_read_subbuffer)(struct libustd_callbacks *data,
				struct buffer_info *buf);

	/**
	 * on_read_partial_subbuffer - Is called when an incomplete subbuffer
	 *			       is being salvaged from an app crash
	 *
	 * @data: pointer to the callbacks structure that has been passed to the
	 *        library.
	 * @buf: structure that contains the data associated with the buffer
	 * @subbuf_index: index of the subbuffer to read in the buffer
	 * @valid_length: number of bytes considered safe to read
	 *
	 * Returns 0 if the callback succeeds else not 0.
	 *
	 * It has to be thread safe, because it is called by many threads.
	 */
	int (*on_read_partial_subbuffer)(struct libustd_callbacks *data,
					struct buffer_info *buf,
					long subbuf_index,
					unsigned long valid_length);

	/**
	 * on_put_error - Is called when a put error has occured and the last
	 *		  subbuffer read is no longer safe to keep
	 *
	 * @data: pointer to the callbacks structure that has been passed to the
	 *        library.
	 * @buf: structure that contains the data associated with the buffer
	 *
	 * Returns 0 if the callback succeeds else not 0.
	 *
	 * It has to be thread safe, because it is called by many threads.
	 */
	int (*on_put_error)(struct libustd_callbacks *data,
				struct buffer_info *buf);

	/**
	 * on_new_thread - Is called when a new thread is created
	 *
	 * @data: pointer to the callbacks structure that has been passed to the
	 *        library.
	 *
	 * Returns 0 if the callback succeeds else not 0.
	 *
	 * It has to be thread safe, because it is called by many threads.
	 */
	int (*on_new_thread)(struct libustd_callbacks *data);

	/**
	 * on_close_thread - Is called just before a thread is destroyed
	 *
	 * @data: pointer to the callbacks structure that has been passed to the
	 *        library.
	 *
	 * Returns 0 if the callback succeeds else not 0.
	 *
	 * It has to be thread safe, because it is called by many threads.
	 */
	int (*on_close_thread)(struct libustd_callbacks *data);

	/**
	 * on_trace_end - Is called at the very end of the tracing session. At
	 * this time, everything has been closed and the threads have
	 * been destroyed.
	 *
	 * @instance: pointer to the instance structure that has been passed to
	 *            the library.
	 *
	 * Returns 0 if the callback succeeds else not 0.
	 *
	 * After this callback is called, no other callback will be called
	 * again and the tracing instance will be deleted automatically by
	 * libustd. After this call, the user must not use the libustd instance.
	 */
	int (*on_trace_end)(struct libustd_instance *instance);

	/**
	 * The library's data.
	 */
	void *user_data;
};

/**
 * libustd_new_instance - Is called to create a new tracing session.
 *
 * @callbacks:    Pointer to a callbacks structure that contain the user
 *                callbacks and data.
 * @sock_path:    Path to the socket used for communication with the traced app
 *
 * Returns the instance if the function succeeds else NULL.
 */
struct libustd_instance *
libustd_new_instance(
	struct libustd_callbacks *callbacks, char *sock_path);

/**
 * libustd_delete_instance - Is called to free a libustd_instance struct
 *
 * @instance: The tracing session instance that needs to be freed.
 *
 * This function should only be called if the instance has not been started,
 * as it will automatically be called at the end of libustd_start_instance.
 */
void libustd_delete_instance(struct libustd_instance *instance);

/**
 * libustd_init_instance - Is called to initiliaze a new tracing session
 *
 * @instance: The tracing session instance that needs to be started.
 *
 * Returns 0 if the function succeeds.
 *
 * This function must be called between libustd_new_instance and
 * libustd_start_instance. It sets up the communication between the library
 * and the tracing application.
 */
int libustd_init_instance(struct libustd_instance *instance);

/**
 * libustd_start_instance - Is called to start a new tracing session.
 *
 * @instance: The tracing session instance that needs to be started.
 *
 * Returns 0 if the function succeeds.
 *
 * This is a blocking function. The caller will be blocked on it until the
 * tracing session is stopped by the user using libustd_stop_instance or until
 * the traced application terminates
 */
int libustd_start_instance(struct libustd_instance *instance);

/**
 * libustd_stop_instance - Is called to stop a tracing session.
 *
 * @instance: The tracing session instance that needs to be stoped.
 * @send_msg: If true, a message will be sent to the listening thread through
 *            the daemon socket to force it to return from the poll syscall
 *            and realize that it must close. This is not necessary if the
 *            instance is being stopped as part of an interrupt handler, as
 *            the interrupt itself will cause poll to return.
 *
 * Returns 0 if the function succeeds.
 *
 * This function returns immediately, it only tells libustd to stop the
 * instance. The on_trace_end callback will be called when the tracing session
 * will really be stopped. The instance is deleted automatically by libustd
 * after on_trace_end is called.
 */
int libustd_stop_instance(struct libustd_instance *instance, int send_msg);

#endif /* USTD_H */

