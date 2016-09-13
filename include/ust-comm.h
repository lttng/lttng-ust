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
#include <lttng/ust-ctl.h>
#include <config.h>

/*
 * Default timeout the application waits for the sessiond to send its
 * "register done" command. Can be overridden with the environment
 * variable "LTTNG_UST_REGISTER_TIMEOUT". Note that if the sessiond is not
 * found, the application proceeds directly without any delay.
 */
#define LTTNG_UST_DEFAULT_CONSTRUCTOR_TIMEOUT_MS	CONFIG_LTTNG_UST_DEFAULT_CONSTRUCTOR_TIMEOUT_MS

#define LTTNG_DEFAULT_RUNDIR				LTTNG_SYSTEM_RUNDIR
#define LTTNG_DEFAULT_HOME_RUNDIR			".lttng"

/* Queue size of listen(2) */
#define LTTNG_UST_COMM_MAX_LISTEN			10
#define LTTNG_UST_COMM_REG_MSG_PADDING			64

struct lttng_event_field;
struct lttng_ctx_field;
struct lttng_enum_entry;
struct lttng_integer_type;
struct lttng_session;

struct ustctl_reg_msg {
	uint32_t magic;
	uint32_t major;
	uint32_t minor;
	uint32_t pid;
	uint32_t ppid;
	uint32_t uid;
	uint32_t gid;
	uint32_t bits_per_long;
	uint32_t uint8_t_alignment;
	uint32_t uint16_t_alignment;
	uint32_t uint32_t_alignment;
	uint32_t uint64_t_alignment;
	uint32_t long_alignment;
	uint32_t socket_type;			/* enum ustctl_socket_type */
	char name[LTTNG_UST_ABI_PROCNAME_LEN];	/* process name */
	char padding[LTTNG_UST_COMM_REG_MSG_PADDING];
} LTTNG_PACKED;

/*
 * Data structure for the commands sent from sessiond to UST.
 */
#define USTCOMM_MSG_PADDING1		32
#define USTCOMM_MSG_PADDING2		32
struct ustcomm_ust_msg {
	uint32_t handle;
	uint32_t cmd;
	char padding[USTCOMM_MSG_PADDING1];
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
		struct {
			uint32_t count;	/* how many names follow */
		} LTTNG_PACKED exclusion;
		char padding[USTCOMM_MSG_PADDING2];
	} u;
} LTTNG_PACKED;

/*
 * Data structure for the response from UST to the session daemon.
 * cmd_type is sent back in the reply for validation.
 */
#define USTCOMM_REPLY_PADDING1		32
#define USTCOMM_REPLY_PADDING2		32
struct ustcomm_ust_reply {
	uint32_t handle;
	uint32_t cmd;
	int32_t ret_code;	/* enum ustcomm_return_code */
	uint32_t ret_val;	/* return value */
	char padding[USTCOMM_REPLY_PADDING1];
	union {
		struct {
			uint64_t memory_map_size;
		} LTTNG_PACKED channel;
		struct {
			uint64_t memory_map_size;
		} LTTNG_PACKED stream;
		struct lttng_ust_tracer_version version;
		struct lttng_ust_tracepoint_iter tracepoint;
		char padding[USTCOMM_REPLY_PADDING2];
	} u;
} LTTNG_PACKED;

struct ustcomm_notify_hdr {
	uint32_t notify_cmd;
} LTTNG_PACKED;

#define USTCOMM_NOTIFY_EVENT_MSG_PADDING	32
struct ustcomm_notify_event_msg {
	uint32_t session_objd;
	uint32_t channel_objd;
	char event_name[LTTNG_UST_SYM_NAME_LEN];
	int32_t loglevel;
	uint32_t signature_len;
	uint32_t fields_len;
	uint32_t model_emf_uri_len;
	char padding[USTCOMM_NOTIFY_EVENT_MSG_PADDING];
	/* followed by signature, fields, and model_emf_uri */
} LTTNG_PACKED;

#define USTCOMM_NOTIFY_EVENT_REPLY_PADDING	32
struct ustcomm_notify_event_reply {
	int32_t ret_code;	/* 0: ok, negative: error code */
	uint32_t event_id;
	char padding[USTCOMM_NOTIFY_EVENT_REPLY_PADDING];
} LTTNG_PACKED;

#define USTCOMM_NOTIFY_ENUM_MSG_PADDING		32
struct ustcomm_notify_enum_msg {
	uint32_t session_objd;
	char enum_name[LTTNG_UST_SYM_NAME_LEN];
	uint32_t entries_len;
	char padding[USTCOMM_NOTIFY_ENUM_MSG_PADDING];
	/* followed by enum entries */
} LTTNG_PACKED;

#define USTCOMM_NOTIFY_EVENT_REPLY_PADDING	32
struct ustcomm_notify_enum_reply {
	int32_t ret_code;	/* 0: ok, negative: error code */
	uint64_t enum_id;
	char padding[USTCOMM_NOTIFY_EVENT_REPLY_PADDING];
} LTTNG_PACKED;

#define USTCOMM_NOTIFY_CHANNEL_MSG_PADDING	32
struct ustcomm_notify_channel_msg {
	uint32_t session_objd;
	uint32_t channel_objd;
	uint32_t ctx_fields_len;
	char padding[USTCOMM_NOTIFY_CHANNEL_MSG_PADDING];
	/* followed by context fields */
} LTTNG_PACKED;

#define USTCOMM_NOTIFY_CHANNEL_REPLY_PADDING	32
struct ustcomm_notify_channel_reply {
	int32_t ret_code;	/* 0: ok, negative: error code */
	uint32_t chan_id;
	uint32_t header_type;	/* enum ustctl_channel_header */
	char padding[USTCOMM_NOTIFY_CHANNEL_REPLY_PADDING];
} LTTNG_PACKED;

/*
 * LTTNG_UST_TRACEPOINT_FIELD_LIST reply is followed by a
 * struct lttng_ust_field_iter field.
 */

extern int ustcomm_create_unix_sock(const char *pathname);
extern int ustcomm_connect_unix_sock(const char *pathname,
		long timeout);
extern int ustcomm_accept_unix_sock(int sock);
extern int ustcomm_listen_unix_sock(int sock);
extern int ustcomm_close_unix_sock(int sock);

extern ssize_t ustcomm_recv_unix_sock(int sock, void *buf, size_t len);
extern ssize_t ustcomm_send_unix_sock(int sock, const void *buf, size_t len);
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
		void **chan_data, uint64_t len, int *wakeup_fd);
int ustcomm_recv_stream_from_sessiond(int sock,
		uint64_t *memory_map_size,
		int *shm_fd, int *wakeup_fd);

/*
 * Returns 0 on success, negative error value on error.
 * Returns -EPIPE or -ECONNRESET if other end has hung up.
 */
int ustcomm_send_reg_msg(int sock,
		enum ustctl_socket_type type,
		uint32_t bits_per_long,
		uint32_t uint8_t_alignment,
		uint32_t uint16_t_alignment,
		uint32_t uint32_t_alignment,
		uint32_t uint64_t_alignment,
		uint32_t long_alignment);

/*
 * Returns 0 on success, negative error value on error.
 * Returns -EPIPE or -ECONNRESET if other end has hung up.
 */
int ustcomm_register_event(int sock,
	struct lttng_session *session,
	int session_objd,		/* session descriptor */
	int channel_objd,		/* channel descriptor */
	const char *event_name,		/* event name (input) */
	int loglevel,
	const char *signature,		/* event signature (input) */
	size_t nr_fields,		/* fields */
	const struct lttng_event_field *fields,
	const char *model_emf_uri,
	uint32_t *id);			/* event id (output) */

/*
 * Returns 0 on success, negative error value on error.
 * Returns -EPIPE or -ECONNRESET if other end has hung up.
 */
int ustcomm_register_enum(int sock,
	int session_objd,		/* session descriptor */
	const char *enum_name,		/* enum name (input) */
	size_t nr_entries,		/* entries */
	const struct lttng_enum_entry *entries,
	uint64_t *id);			/* enum id (output) */

/*
 * Returns 0 on success, negative error value on error.
 * Returns -EPIPE or -ECONNRESET if other end has hung up.
 */
int ustcomm_register_channel(int sock,
	struct lttng_session *session,
	int session_objd,		/* session descriptor */
	int channel_objd,		/* channel descriptor */
	size_t nr_ctx_fields,
	const struct lttng_ctx_field *ctx_fields,
	uint32_t *chan_id,		/* channel id (output) */
	int *header_type); 		/* header type (output) */

int ustcomm_setsockopt_rcv_timeout(int sock, unsigned int msec);
int ustcomm_setsockopt_snd_timeout(int sock, unsigned int msec);

#endif	/* _LTTNG_UST_COMM_H */
