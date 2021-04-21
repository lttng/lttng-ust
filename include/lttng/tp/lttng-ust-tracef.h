/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2011-2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include <lttng/tracepoint.h>
#include <stdarg.h>

LTTNG_UST_TRACEPOINT_EVENT(lttng_ust_tracef, event,
	LTTNG_UST_TP_ARGS(const char *, msg, unsigned int, len, void *, ip),
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_sequence_text(char, msg, msg, unsigned int, len)
		ctf_unused(ip)
	)
)
LTTNG_UST_TRACEPOINT_LOGLEVEL(lttng_ust_tracef, event, LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG)
