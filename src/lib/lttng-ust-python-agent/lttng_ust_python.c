/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2014 David Goulet <dgoulet@efficios.com>
 */

#define _LGPL_SOURCE
#define LTTNG_UST_TRACEPOINT_DEFINE
#define LTTNG_UST_TRACEPOINT_CREATE_PROBES
#include "lttng_ust_python.h"

/*
 * The tracepoint fired by the agent.
 */

void py_tracepoint(const char *asctime, const char *msg,
		const char *logger_name, const char *funcName, unsigned int lineno,
		unsigned int int_loglevel, unsigned int thread, const char *threadName);
void py_tracepoint(const char *asctime, const char *msg,
		const char *logger_name, const char *funcName, unsigned int lineno,
		unsigned int int_loglevel, unsigned int thread, const char *threadName)
{
	lttng_ust_tracepoint(lttng_python, event, asctime, msg, logger_name, funcName,
			lineno, int_loglevel, thread, threadName);
}
