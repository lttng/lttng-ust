#ifndef _LTTNG_UST_COMM_H
#define _LTTNG_UST_COMM_H

/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *                      Julien Desfossez <julien.desfossez@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; only
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/*
 * This header is meant for liblttng and libust internal use ONLY.
 * These declarations should NOT be considered stable API.
 */

#include <limits.h>
#include <unistd.h>
#include <lttng/ust-abi.h>
#include <lttng/ust-error.h>
#include <lttng/ust-compiler.h>

/*
 * Default timeout the application waits for the sessiond to send its
 * "register done" command. Can be overridden with the environment
 * variable "LTTNG_UST_REGISTER_TIMEOUT". Note that if the sessiond is not
 * found, the application proceeds directly without any delay.
 */
#define LTTNG_UST_DEFAULT_CONSTRUCTOR_TIMEOUT_MS	3000

#define LTTNG_RUNDIR                        "/var/run/lttng"
#define LTTNG_HOME_RUNDIR                   "%s/.lttng"

/* Default unix socket path */
#define DEFAULT_GLOBAL_CLIENT_UNIX_SOCK     LTTNG_RUNDIR "/client-lttng-sessiond"
#define DEFAULT_GLOBAL_APPS_UNIX_SOCK       LTTNG_RUNDIR "/apps-lttng-sessiond"
#define DEFAULT_HOME_APPS_UNIX_SOCK         LTTNG_HOME_RUNDIR "/apps-lttng-sessiond"
#define DEFAULT_HOME_CLIENT_UNIX_SOCK       LTTNG_HOME_RUNDIR "/client-lttng-sessiond"

#define DEFAULT_GLOBAL_APPS_WAIT_SHM_PATH   "/lttng-ust-apps-wait"
#define DEFAULT_HOME_APPS_WAIT_SHM_PATH     "/lttng-ust-apps-wait-%u"

/* Queue size of listen(2) */
#define LTTNG_UST_COMM_MAX_LISTEN 10

/*
 * Data structure for the commands sent from sessiond to UST.
 */
struct ustcomm_ust_msg {
	uint32_t handle;
	uint32_t cmd;
	union {
		struct lttng_ust_channel channel;
		struct lttng_ust_stream stream;
		struct lttng_ust_event event;
		struct lttng_ust_context context;
		struct lttng_ust_tracer_version version;
		struct lttng_ust_tracepoint_iter tracepoint;
		struct {
			uint32_t data_size;	/* following filter data */
			uint32_t reloc_offset;
			uint64_t seqnum;
		} LTTNG_PACKED filter;
	} u;
} LTTNG_PACKED;

/*
 * Data structure for the response from UST to the session daemon.
 * cmd_type is sent back in the reply for validation.
 */
struct ustcomm_ust_reply {
	uint32_t handle;
	uint32_t cmd;
	uint32_t ret_code;	/* enum enum ustcomm_return_code */
	uint32_t ret_val;	/* return value */
	union {
		struct {
			uint64_t memory_map_size;
		} LTTNG_PACKED channel;
		struct {
			uint64_t memory_map_size;
		} LTTNG_PACKED stream;
		struct lttng_ust_tracer_version version;
		struct lttng_ust_tracepoint_iter tracepoint;
	} u;
} LTTNG_PACKED;

/*
 * LTTNG_UST_TRACEPOINT_FIELD_LIST reply is followed by a
 * struct lttng_ust_field_iter field.
 */

extern int ustcomm_create_unix_sock(const char *pathname);
extern int ustcomm_connect_unix_sock(const char *pathname);
extern int ustcomm_accept_unix_sock(int sock);
extern int ustcomm_listen_unix_sock(int sock);
extern int ustcomm_close_unix_sock(int sock);

extern ssize_t ustcomm_recv_unix_sock(int sock, void *buf, size_t len);
extern ssize_t ustcomm_send_unix_sock(int sock, void *buf, size_t len);
extern ssize_t ustcomm_send_fds_unix_sock(int sock, int *fds, size_t nb_fd);
extern ssize_t ustcomm_recv_fds_unix_sock(int sock, int *fds, size_t nb_fd);

extern const char *ustcomm_get_readable_code(int code);
extern int ustcomm_send_app_msg(int sock, struct ustcomm_ust_msg *lum);
extern int ustcomm_recv_app_reply(int sock, struct ustcomm_ust_reply *lur,
		uint32_t expected_handle, uint32_t expected_cmd);
extern int ustcomm_send_app_cmd(int sock,
		struct ustcomm_ust_msg *lum,
		struct ustcomm_ust_reply *lur);
int ustcomm_recv_fd(int sock);

ssize_t ustcomm_recv_channel_from_sessiond(int sock,
		void **chan_data, uint64_t len);
int ustcomm_recv_stream_from_sessiond(int sock,
		uint64_t *memory_map_size,
		int *shm_fd, int *wakeup_fd);

#endif	/* _LTTNG_UST_COMM_H */
