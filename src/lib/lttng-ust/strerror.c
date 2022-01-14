/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011 EfficiOS Inc.
 * Copyright (C) 2011-2013 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include <lttng/ust-error.h>

#define CODE_OFFSET(code)	\
	(code == LTTNG_UST_OK ? 0 : (code - LTTNG_UST_ERR + 1))

/*
 * Human readable error message.
 */
static const char *ustcomm_readable_code[] = {
	[ CODE_OFFSET(LTTNG_UST_OK) ] = "Success",
	[ CODE_OFFSET(LTTNG_UST_ERR) ] = "Unknown error",
	[ CODE_OFFSET(LTTNG_UST_ERR_NOENT) ] = "No entry",
	[ CODE_OFFSET(LTTNG_UST_ERR_EXIST) ] = "Object already exists",
	[ CODE_OFFSET(LTTNG_UST_ERR_INVAL) ] = "Invalid argument",
	[ CODE_OFFSET(LTTNG_UST_ERR_PERM) ] = "Permission denied",
	[ CODE_OFFSET(LTTNG_UST_ERR_NOSYS) ] = "Not implemented",
	[ CODE_OFFSET(LTTNG_UST_ERR_EXITING) ] = "Process is exiting",

	[ CODE_OFFSET(LTTNG_UST_ERR_INVAL_MAGIC) ] = "Invalid magic number",
	[ CODE_OFFSET(LTTNG_UST_ERR_INVAL_SOCKET_TYPE) ] = "Invalid socket type",
	[ CODE_OFFSET(LTTNG_UST_ERR_UNSUP_MAJOR) ] = "Unsupported major version",
	[ CODE_OFFSET(LTTNG_UST_ERR_PEERCRED) ] = "Cannot get unix socket peer credentials",
	[ CODE_OFFSET(LTTNG_UST_ERR_PEERCRED_PID) ] = "Peer credentials PID is invalid. Socket appears to belong to a distinct, non-nested pid namespace.",
};

/*
 * lttng_ust_strerror
 * @code: must be a negative value of enum lttng_ust_error_code (or 0).
 *
 * Returns a ptr to a string representing a human readable error code from the
 * ustcomm_return_code enum.
 */
const char *lttng_ust_strerror(int code)
{
	code = -code;

	if (code < LTTNG_UST_OK || code >= LTTNG_UST_ERR_NR)
		code = LTTNG_UST_ERR;

	return ustcomm_readable_code[CODE_OFFSET(code)];
}
