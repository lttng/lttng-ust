/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011 EfficiOS Inc.
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

/*
 * This header is meant for liblttng and libust internal use ONLY.
 * These declarations should NOT be considered stable API.
 */

#ifndef _UST_COMMON_UST_COMM_H
#define _UST_COMMON_UST_COMM_H

#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#include <lttng/ust-abi.h>
#include <lttng/ust-abi-old.h>
#include <lttng/ust-error.h>
#include <lttng/ust-compiler.h>
#include <lttng/ust-ctl.h>

/*
 * Default timeout the application waits for the sessiond to send its
 * "register done" command. Can be overridden with the environment
 * variable "LTTNG_UST_REGISTER_TIMEOUT". Note that if the sessiond is not
 * found, the application proceeds directly without any delay.
 */
#define LTTNG_UST_DEFAULT_CONSTRUCTOR_TIMEOUT_MS	3000

#define LTTNG_DEFAULT_RUNDIR				LTTNG_SYSTEM_RUNDIR
#define LTTNG_DEFAULT_HOME_RUNDIR			".lttng"

/* Queue size of listen(2) */
#define LTTNG_UST_COMM_MAX_LISTEN			10
#define LTTNG_UST_COMM_REG_MSG_PADDING			64

struct lttng_ust_event_field;
struct lttng_ust_ctx_field;
struct lttng_ust_enum_entry;
struct lttng_integer_type;
struct lttng_ust_session;

struct lttng_ust_ctl_reg_msg {
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
	uint32_t socket_type;			/* enum lttng_ust_ctl_socket_type */
	char name[LTTNG_UST_ABI_PROCNAME_LEN];	/* process name */
	char padding[LTTNG_UST_COMM_REG_MSG_PADDING];
} __attribute__((packed));

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
		struct lttng_ust_abi_channel channel;
		struct lttng_ust_abi_stream stream;
		struct lttng_ust_abi_event event;
		struct lttng_ust_abi_context context;
		struct lttng_ust_abi_tracer_version version;
		struct lttng_ust_abi_tracepoint_iter tracepoint;
		struct {
			uint32_t data_size;	/* following filter data */
			uint32_t reloc_offset;
			uint64_t seqnum;
		} __attribute__((packed)) filter;
		struct {
			uint32_t count;	/* how many names follow */
		} __attribute__((packed)) exclusion;
		struct {
			uint32_t data_size;	/* following capture data */
			uint32_t reloc_offset;
			uint64_t seqnum;
		} __attribute__((packed)) capture;
		struct lttng_ust_abi_old_counter counter_old;
		struct lttng_ust_abi_old_counter_channel counter_channel_old;
		struct lttng_ust_abi_old_counter_cpu counter_cpu_old;
		struct {
			uint32_t cmd_len;
		} __attribute__((packed)) var_len_cmd;
		char padding[USTCOMM_MSG_PADDING2];
	} u;
} __attribute__((packed));

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
		} __attribute__((packed)) channel;
		struct {
			uint64_t memory_map_size;
		} __attribute__((packed)) stream;
		struct lttng_ust_abi_tracer_version version;
		struct lttng_ust_abi_tracepoint_iter tracepoint;
		char padding[USTCOMM_REPLY_PADDING2];
	} u;
} __attribute__((packed));

struct ustcomm_notify_hdr {
	uint32_t notify_cmd;
} __attribute__((packed));

#define USTCOMM_NOTIFY_EVENT_MSG_PADDING	24
struct ustcomm_notify_event_msg {
	uint32_t session_objd;
	uint32_t channel_objd;
	char event_name[LTTNG_UST_ABI_SYM_NAME_LEN];
	int32_t loglevel;
	uint32_t signature_len;
	uint32_t fields_len;
	uint32_t model_emf_uri_len;
	uint64_t user_token;
	char padding[USTCOMM_NOTIFY_EVENT_MSG_PADDING];
	/* followed by signature, fields, and model_emf_uri */
} __attribute__((packed));

#define USTCOMM_NOTIFY_EVENT_REPLY_PADDING	32
struct ustcomm_notify_event_reply {
	int32_t ret_code;	/* 0: ok, negative: error code */
	uint32_t id;	/* 32-bit event id. */
	char padding[USTCOMM_NOTIFY_EVENT_REPLY_PADDING];
} __attribute__((packed));

#define USTCOMM_NOTIFY_KEY_MSG_PADDING	24
struct ustcomm_notify_key_msg {
	uint32_t session_objd;
	uint32_t map_objd;
	uint32_t dimension;
	uint32_t key_string_len;
	uint64_t user_token;
	char padding[USTCOMM_NOTIFY_KEY_MSG_PADDING];
	/* followed by dimension_indexes (array of @dimension uint64_t items) and key_string. */
} __attribute__((packed));

#define USTCOMM_NOTIFY_KEY_REPLY_PADDING	32
struct ustcomm_notify_key_reply {
	int32_t ret_code;	/* 0: ok, negative: error code */
	uint64_t index;		/* 64-bit key index. */
	char padding[USTCOMM_NOTIFY_KEY_REPLY_PADDING];
} __attribute__((packed));

#define USTCOMM_NOTIFY_ENUM_MSG_PADDING		32
struct ustcomm_notify_enum_msg {
	uint32_t session_objd;
	char enum_name[LTTNG_UST_ABI_SYM_NAME_LEN];
	uint32_t entries_len;
	char padding[USTCOMM_NOTIFY_ENUM_MSG_PADDING];
	/* followed by enum entries */
} __attribute__((packed));

#define USTCOMM_NOTIFY_ENUM_REPLY_PADDING	32
struct ustcomm_notify_enum_reply {
	int32_t ret_code;	/* 0: ok, negative: error code */
	uint64_t enum_id;
	char padding[USTCOMM_NOTIFY_ENUM_REPLY_PADDING];
} __attribute__((packed));

#define USTCOMM_NOTIFY_CHANNEL_MSG_PADDING	32
struct ustcomm_notify_channel_msg {
	uint32_t session_objd;
	uint32_t channel_objd;
	uint32_t ctx_fields_len;
	char padding[USTCOMM_NOTIFY_CHANNEL_MSG_PADDING];
	/* followed by context fields */
} __attribute__((packed));

#define USTCOMM_NOTIFY_CHANNEL_REPLY_PADDING	32
struct ustcomm_notify_channel_reply {
	int32_t ret_code;	/* 0: ok, negative: error code */
	uint32_t chan_id;
	uint32_t header_type;	/* enum lttng_ust_ctl_channel_header */
	char padding[USTCOMM_NOTIFY_CHANNEL_REPLY_PADDING];
} __attribute__((packed));

/*
 * LTTNG_UST_TRACEPOINT_FIELD_LIST reply is followed by a
 * struct lttng_ust_field_iter field.
 */

int ustcomm_create_unix_sock(const char *pathname)
	__attribute__((visibility("hidden")));

int ustcomm_connect_unix_sock(const char *pathname,
	long timeout)
	__attribute__((visibility("hidden")));

int ustcomm_accept_unix_sock(int sock)
	__attribute__((visibility("hidden")));

int ustcomm_listen_unix_sock(int sock)
	__attribute__((visibility("hidden")));

int ustcomm_shutdown_unix_sock(int sock)
	__attribute__((visibility("hidden")));

int ustcomm_close_unix_sock(int sock)
	__attribute__((visibility("hidden")));

ssize_t ustcomm_recv_unix_sock(int sock, void *buf, size_t len)
	__attribute__((visibility("hidden")));

ssize_t ustcomm_send_unix_sock(int sock, const void *buf, size_t len)
	__attribute__((visibility("hidden")));

ssize_t ustcomm_send_fds_unix_sock(int sock, int *fds, size_t nb_fd)
	__attribute__((visibility("hidden")));

ssize_t ustcomm_recv_fds_unix_sock(int sock, int *fds, size_t nb_fd)
	__attribute__((visibility("hidden")));

const char *ustcomm_get_readable_code(int code)
	__attribute__((visibility("hidden")));

int ustcomm_send_app_msg(int sock, struct ustcomm_ust_msg *lum)
	__attribute__((visibility("hidden")));

int ustcomm_recv_app_reply(int sock, struct ustcomm_ust_reply *lur,
	uint32_t expected_handle, uint32_t expected_cmd)
	__attribute__((visibility("hidden")));

int ustcomm_send_app_cmd(int sock,
		struct ustcomm_ust_msg *lum,
		struct ustcomm_ust_reply *lur)
	__attribute__((visibility("hidden")));

int ustcomm_recv_fd(int sock)
	__attribute__((visibility("hidden")));

ssize_t ustcomm_recv_channel_from_sessiond(int sock,
		void **chan_data, uint64_t len, int *wakeup_fd)
	__attribute__((visibility("hidden")));

int ustcomm_recv_stream_from_sessiond(int sock,
		uint64_t *memory_map_size,
		int *shm_fd, int *wakeup_fd)
	__attribute__((visibility("hidden")));

ssize_t ustcomm_recv_event_notifier_notif_fd_from_sessiond(int sock,
		int *event_notifier_notif_fd)
	__attribute__((visibility("hidden")));

ssize_t ustcomm_recv_var_len_cmd_from_sessiond(int sock,
		void **data, uint32_t len)
	__attribute__((visibility("hidden")));

int ustcomm_recv_counter_shm_from_sessiond(int sock,
		int *shm_fd)
	__attribute__((visibility("hidden")));

/*
 * Returns 0 on success, negative error value on error.
 * Returns -EPIPE or -ECONNRESET if other end has hung up.
 */
int ustcomm_send_reg_msg(int sock,
		enum lttng_ust_ctl_socket_type type,
		uint32_t bits_per_long,
		uint32_t uint8_t_alignment,
		uint32_t uint16_t_alignment,
		uint32_t uint32_t_alignment,
		uint32_t uint64_t_alignment,
		uint32_t long_alignment,
		const char *procname)
	__attribute__((visibility("hidden")));

/*
 * Returns 0 on success, negative error value on error.
 * Returns -EPIPE or -ECONNRESET if other end has hung up.
 */
int ustcomm_register_event(int sock,
	struct lttng_ust_session *session,
	int session_objd,		/* session descriptor */
	int channel_objd,		/* channel descriptor */
	const char *event_name,		/* event name (input) */
	int loglevel,
	const char *signature,		/* event signature (input) */
	size_t nr_fields,		/* fields */
	const struct lttng_ust_event_field * const *fields,
	const char *model_emf_uri,
	uint64_t user_token,
	uint32_t *id)			/* (output) */
	__attribute__((visibility("hidden")));

#ifdef CONFIG_LTTNG_UST_EXPERIMENTAL_COUNTER
/*
 * Returns 0 on success, negative error value on error.
 * Returns -EPIPE or -ECONNRESET if other end has hung up.
 */
int ustcomm_register_key(int sock,
	int session_objd,		/* session descriptor */
	int map_objd,			/* map descriptor */
	uint32_t dimension,
	const uint64_t *dimension_indexes,
	const char *key_string,		/* key string (input) */
	uint64_t user_token,
	uint64_t *index)		/* (output) */
	__attribute__((visibility("hidden")));
#endif	/* CONFIG_LTTNG_UST_EXPERIMENTAL_COUNTER */

/*
 * Returns 0 on success, negative error value on error.
 * Returns -EPIPE or -ECONNRESET if other end has hung up.
 */
int ustcomm_register_enum(int sock,
	int session_objd,		/* session descriptor */
	const char *enum_name,		/* enum name (input) */
	size_t nr_entries,		/* entries */
	const struct lttng_ust_enum_entry * const *entries,
	uint64_t *id)			/* enum id (output) */
	__attribute__((visibility("hidden")));

/*
 * Returns 0 on success, negative error value on error.
 * Returns -EPIPE or -ECONNRESET if other end has hung up.
 */
int ustcomm_register_channel(int sock,
	struct lttng_ust_session *session,
	int session_objd,		/* session descriptor */
	int channel_objd,		/* channel descriptor */
	size_t nr_ctx_fields,
	struct lttng_ust_ctx_field *ctx_fields,
	uint32_t *chan_id,		/* channel id (output) */
	int *header_type) 		/* header type (output) */
	__attribute__((visibility("hidden")));

int ustcomm_setsockopt_rcv_timeout(int sock, unsigned int msec)
	__attribute__((visibility("hidden")));

int ustcomm_setsockopt_snd_timeout(int sock, unsigned int msec)
	__attribute__((visibility("hidden")));

#endif	/* _UST_COMMON_UST_COMM_H */
