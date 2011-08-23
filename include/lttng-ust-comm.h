#ifndef _LTTNG_UST_COMM_H
#define _LTTNG_UST_COMM_H

/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *                      Julien Desfossez <julien.desfossez@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; only version 2
 * of the License.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/*
 * This header is meant for liblttng and libust internal use ONLY.
 * These declarations should NOT be considered stable API.
 */

#include <limits.h>
#include <lttng/lttng.h>
#include <ust/lttng-ust-abi.h>

/*
 * Default timeout the application waits for the sessiond to send its
 * "register done" command. Can be overridden with the environment
 * variable "UST_REGISTER_TIMEOUT". Note that if the sessiond is not
 * found, the application proceeds directly without any delay.
 */
#define LTTNG_UST_DEFAULT_CONSTRUCTOR_TIMEOUT_MS	3000

#define LTTNG_RUNDIR                        "/var/run/lttng"

/* Default unix socket path */
#define DEFAULT_GLOBAL_CLIENT_UNIX_SOCK     LTTNG_RUNDIR "/client-ltt-sessiond"
#define DEFAULT_GLOBAL_APPS_UNIX_SOCK       LTTNG_RUNDIR "/apps-ltt-sessiond"
#define DEFAULT_HOME_APPS_UNIX_SOCK         "%s/.apps-ltt-sessiond"
#define DEFAULT_HOME_CLIENT_UNIX_SOCK       "%s/.client-ltt-sessiond"

/* Queue size of listen(2) */
#define MAX_LISTEN 10

/* Get the error code index from 0 since
 * LTTCOMM_OK start at 1000
 */
#define LTTCOMM_ERR_INDEX(code) (code - LTTCOMM_OK)

/*
 * lttcomm error code.
 */
enum lttcomm_return_code {
	LTTCOMM_OK = 1000,				/* Ok */
	LTTCOMM_ERR,					/* Unknown Error */
	LTTCOMM_UND,					/* Undefine command */
	LTTCOMM_NOT_IMPLEMENTED,        /* Command not implemented */
	LTTCOMM_UNKNOWN_DOMAIN,         /* Tracing domain not known */
	LTTCOMM_ALLOC_FAIL,				/* Trace allocation fail */
	LTTCOMM_NO_SESSION,				/* No session found */
	LTTCOMM_CREATE_FAIL,			/* Create trace fail */
	LTTCOMM_SESSION_FAIL,			/* Create session fail */
	LTTCOMM_START_FAIL,				/* Start tracing fail */
	LTTCOMM_STOP_FAIL,				/* Stop tracing fail */
	LTTCOMM_LIST_FAIL,				/* Listing apps fail */
	LTTCOMM_NO_APPS,				/* No traceable application */
	LTTCOMM_SESS_NOT_FOUND,			/* Session name not found */
	LTTCOMM_NO_TRACE,				/* No trace exist */
	LTTCOMM_FATAL,					/* Session daemon had a fatal error */
	LTTCOMM_NO_TRACEABLE,			/* Error for non traceable app */
	LTTCOMM_SELECT_SESS,			/* Must select a session */
	LTTCOMM_EXIST_SESS,				/* Session name already exist */
	LTTCOMM_NO_EVENT,				/* No event found */
	LTTCOMM_KERN_NA,				/* Kernel tracer unavalable */
	LTTCOMM_KERN_EVENT_EXIST,       /* Kernel event already exists */
	LTTCOMM_KERN_SESS_FAIL,			/* Kernel create session failed */
	LTTCOMM_KERN_CHAN_FAIL,			/* Kernel create channel failed */
	LTTCOMM_KERN_CHAN_NOT_FOUND,	/* Kernel channel not found */
	LTTCOMM_KERN_CHAN_DISABLE_FAIL, /* Kernel disable channel failed */
	LTTCOMM_KERN_CHAN_ENABLE_FAIL,  /* Kernel enable channel failed */
	LTTCOMM_KERN_CONTEXT_FAIL,      /* Kernel add context failed */
	LTTCOMM_KERN_ENABLE_FAIL,		/* Kernel enable event failed */
	LTTCOMM_KERN_DISABLE_FAIL,		/* Kernel disable event failed */
	LTTCOMM_KERN_META_FAIL,			/* Kernel open metadata failed */
	LTTCOMM_KERN_START_FAIL,		/* Kernel start trace failed */
	LTTCOMM_KERN_STOP_FAIL,			/* Kernel stop trace failed */
	LTTCOMM_KERN_CONSUMER_FAIL,		/* Kernel consumer start failed */
	LTTCOMM_KERN_STREAM_FAIL,		/* Kernel create stream failed */
	LTTCOMM_KERN_DIR_FAIL,			/* Kernel trace directory creation failed */
	LTTCOMM_KERN_DIR_EXIST,			/* Kernel trace directory exist */
	LTTCOMM_KERN_NO_SESSION,		/* No kernel session found */
	LTTCOMM_KERN_LIST_FAIL,			/* Kernel listing events failed */
	KCONSUMERD_COMMAND_SOCK_READY,	/* when kconsumerd command socket ready */
	KCONSUMERD_SUCCESS_RECV_FD,		/* success on receiving fds */
	KCONSUMERD_ERROR_RECV_FD,		/* error on receiving fds */
	KCONSUMERD_POLL_ERROR,			/* Error in polling thread in kconsumerd */
	KCONSUMERD_POLL_NVAL,			/* Poll on closed fd */
	KCONSUMERD_POLL_HUP,			/* All fds have hungup */
	KCONSUMERD_EXIT_SUCCESS,		/* kconsumerd exiting normally */
	KCONSUMERD_EXIT_FAILURE,		/* kconsumerd exiting on error */
	KCONSUMERD_OUTFD_ERROR,			/* error opening the tracefile */
	KCONSUMERD_SPLICE_EBADF,		/* EBADF from splice(2) */
	KCONSUMERD_SPLICE_EINVAL,		/* EINVAL from splice(2) */
	KCONSUMERD_SPLICE_ENOMEM,		/* ENOMEM from splice(2) */
	KCONSUMERD_SPLICE_ESPIPE,		/* ESPIPE from splice(2) */
	/* MUST be last element */
	LTTCOMM_NR,						/* Last element */
};

/*
 * Data structure for the commands sent from sessiond to UST.
 */
struct lttcomm_ust_msg {
	uint32_t handle;
	uint32_t cmd;
	union {
		struct lttng_ust_tracer_version version;
		struct lttng_ust_channel channel;
		struct lttng_ust_event event;
		struct lttng_ust_context context;
	} u;
};

/*
 * Data structure for the response from UST to the session daemon.
 * cmd_type is sent back in the reply for validation.
 */
struct lttcomm_ust_reply {
	uint32_t handle;
	uint32_t cmd;
	uint32_t ret_code;	/* enum enum lttcomm_return_code */
	uint32_t ret_val;	/* return value */
	union {
	} u;
};

extern int lttcomm_create_unix_sock(const char *pathname);
extern int lttcomm_connect_unix_sock(const char *pathname);
extern int lttcomm_accept_unix_sock(int sock);
extern int lttcomm_listen_unix_sock(int sock);
extern int lttcomm_close_unix_sock(int sock);
/* Send fd(s) over a unix socket. */
extern ssize_t lttcomm_send_fds_unix_sock(int sock, void *buf, int *fds,
		size_t nb_fd, size_t len);
extern ssize_t lttcomm_recv_unix_sock(int sock, void *buf, size_t len);
extern ssize_t lttcomm_send_unix_sock(int sock, void *buf, size_t len);
extern const char *lttcomm_get_readable_code(enum lttcomm_return_code code);

#endif	/* _LTTNG_UST_COMM_H */
