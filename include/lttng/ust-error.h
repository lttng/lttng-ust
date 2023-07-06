// SPDX-FileCopyrightText: 2011 EfficiOS Inc.
// SPDX-FileCopyrightText: 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
//
// SPDX-License-Identifier: LGPL-2.1-only

#ifndef _LTTNG_UST_ERROR_H
#define _LTTNG_UST_ERROR_H

#include <limits.h>
#include <unistd.h>
#include <lttng/ust-abi.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ustcomm error code.
 */
enum lttng_ust_error_code {
	LTTNG_UST_OK = 0,			/* Ok */
	LTTNG_UST_ERR = 1024,			/* Unknown Error */
	LTTNG_UST_ERR_NOENT = 1025,		/* No entry */
	LTTNG_UST_ERR_EXIST = 1026,		/* Object exists */
	LTTNG_UST_ERR_INVAL = 1027,		/* Invalid argument */
	LTTNG_UST_ERR_PERM  = 1028,		/* Permission denied */
	LTTNG_UST_ERR_NOSYS = 1029,		/* Not implemented */
	LTTNG_UST_ERR_EXITING = 1030,		/* Process is exiting */

	LTTNG_UST_ERR_INVAL_MAGIC = 1031,	/* Invalid magic number */
	LTTNG_UST_ERR_INVAL_SOCKET_TYPE = 1032,	/* Invalid socket type */
	LTTNG_UST_ERR_UNSUP_MAJOR = 1033,	/* Unsupported major version */
	LTTNG_UST_ERR_PEERCRED = 1034,		/* Cannot get unix socket peer credentials */
	LTTNG_UST_ERR_PEERCRED_PID = 1035,	/* Peer credentials PID is invalid. Socket appears to belong to a distinct, non-nested pid namespace. */

	/* MUST be last element */
	LTTNG_UST_ERR_NR,			/* Last element */
};

/*
 * lttng_ust_strerror
 * @code: must be a negative value of enum lttng_ust_error_code (or 0).
 *
 * Returns a ptr to a string representing a human readable error code from the
 * ustcomm_return_code enum.
 */
const char *lttng_ust_strerror(int code);

#ifdef __cplusplus
}
#endif

#endif	/* _LTTNG_UST_ERROR_H */
