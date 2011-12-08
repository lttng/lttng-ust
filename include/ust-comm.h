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

/* Get the error code index from 0. USTCOMM_ERR starts at 1000.
 */
#define USTCOMM_ERR_INDEX(code) (code - USTCOMM_ERR)

/*
 * ustcomm error code.
 */
enum ustcomm_return_code {
	USTCOMM_OK = 0,					/* Ok */
	/* Range 1 to 999 used for standard error numbers (errno.h) */
	USTCOMM_ERR = 1000,				/* Unknown Error */
	USTCOMM_UND,					/* Undefine command */
	USTCOMM_NOT_IMPLEMENTED,        /* Command not implemented */
	USTCOMM_UNKNOWN_DOMAIN,         /* Tracing domain not known */
	USTCOMM_ALLOC_FAIL,				/* Trace allocation fail */
	USTCOMM_NO_SESSION,				/* No session found */
	USTCOMM_CREATE_FAIL,			/* Create trace fail */
	USTCOMM_SESSION_FAIL,			/* Create session fail */
	USTCOMM_START_FAIL,				/* Start tracing fail */
	USTCOMM_STOP_FAIL,				/* Stop tracing fail */
	USTCOMM_LIST_FAIL,				/* Listing apps fail */
	USTCOMM_NO_APPS,				/* No traceable application */
	USTCOMM_SESS_NOT_FOUND,			/* Session name not found */
	USTCOMM_NO_TRACE,				/* No trace exist */
	USTCOMM_FATAL,					/* Session daemon had a fatal error */
	USTCOMM_NO_TRACEABLE,			/* Error for non traceable app */
	USTCOMM_SELECT_SESS,			/* Must select a session */
	USTCOMM_EXIST_SESS,				/* Session name already exist */
	USTCOMM_NO_EVENT,				/* No event found */
	USTCOMM_KERN_NA,				/* Kernel tracer unavalable */
	USTCOMM_KERN_EVENT_EXIST,       /* Kernel event already exists */
	USTCOMM_KERN_SESS_FAIL,			/* Kernel create session failed */
	USTCOMM_KERN_CHAN_FAIL,			/* Kernel create channel failed */
	USTCOMM_KERN_CHAN_NOT_FOUND,	/* Kernel channel not found */
	USTCOMM_KERN_CHAN_DISABLE_FAIL, /* Kernel disable channel failed */
	USTCOMM_KERN_CHAN_ENABLE_FAIL,  /* Kernel enable channel failed */
	USTCOMM_KERN_CONTEXT_FAIL,      /* Kernel add context failed */
	USTCOMM_KERN_ENABLE_FAIL,		/* Kernel enable event failed */
	USTCOMM_KERN_DISABLE_FAIL,		/* Kernel disable event failed */
	USTCOMM_KERN_META_FAIL,			/* Kernel open metadata failed */
	USTCOMM_KERN_START_FAIL,		/* Kernel start trace failed */
	USTCOMM_KERN_STOP_FAIL,			/* Kernel stop trace failed */
	USTCOMM_KERN_CONSUMER_FAIL,		/* Kernel consumer start failed */
	USTCOMM_KERN_STREAM_FAIL,		/* Kernel create stream failed */
	USTCOMM_KERN_DIR_FAIL,			/* Kernel trace directory creation failed */
	USTCOMM_KERN_DIR_EXIST,			/* Kernel trace directory exist */
	USTCOMM_KERN_NO_SESSION,		/* No kernel session found */
	USTCOMM_KERN_LIST_FAIL,			/* Kernel listing events failed */
	USTCONSUMER_COMMAND_SOCK_READY,	/* when kconsumerd command socket ready */
	USTCONSUMER_SUCCESS_RECV_FD,		/* success on receiving fds */
	USTCONSUMER_ERROR_RECV_FD,		/* error on receiving fds */
	USTCONSUMER_POLL_ERROR,			/* Error in polling thread in kconsumerd */
	USTCONSUMER_POLL_NVAL,			/* Poll on closed fd */
	USTCONSUMER_POLL_HUP,			/* All fds have hungup */
	USTCONSUMER_EXIT_SUCCESS,		/* kconsumerd exiting normally */
	USTCONSUMER_EXIT_FAILURE,		/* kconsumerd exiting on error */
	USTCONSUMER_OUTFD_ERROR,			/* error opening the tracefile */
	USTCONSUMER_SPLICE_EBADF,		/* EBADF from splice(2) */
	USTCONSUMER_SPLICE_EINVAL,		/* EINVAL from splice(2) */
	USTCONSUMER_SPLICE_ENOMEM,		/* ENOMEM from splice(2) */
	USTCONSUMER_SPLICE_ESPIPE,		/* ESPIPE from splice(2) */
	/* MUST be last element */
	USTCOMM_NR,						/* Last element */
};

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
	} u;
};

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
		} channel;
		struct {
			uint64_t memory_map_size;
		} stream;
		struct lttng_ust_tracer_version version;
		struct lttng_ust_tracepoint_iter tracepoint;
	} u;
};

extern int ustcomm_create_unix_sock(const char *pathname);
extern int ustcomm_connect_unix_sock(const char *pathname);
extern int ustcomm_accept_unix_sock(int sock);
extern int ustcomm_listen_unix_sock(int sock);
extern int ustcomm_close_unix_sock(int sock);
/* Send fd(s) over a unix socket. */
extern ssize_t ustcomm_send_fds_unix_sock(int sock, void *buf, int *fds,
		size_t nb_fd, size_t len);
extern ssize_t ustcomm_recv_unix_sock(int sock, void *buf, size_t len);
extern ssize_t ustcomm_send_unix_sock(int sock, void *buf, size_t len);
extern const char *ustcomm_get_readable_code(int code);
extern int ustcomm_send_app_msg(int sock, struct ustcomm_ust_msg *lum);
extern int ustcomm_recv_app_reply(int sock, struct ustcomm_ust_reply *lur,
		uint32_t expected_handle, uint32_t expected_cmd);
extern int ustcomm_send_app_cmd(int sock,
		struct ustcomm_ust_msg *lum,
		struct ustcomm_ust_reply *lur);
int ustcomm_recv_fd(int sock);

#endif	/* _LTTNG_UST_COMM_H */
