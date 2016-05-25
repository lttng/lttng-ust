/*
 * Copyright (C) 2014 - David Goulet <dgoulet@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#define _LGPL_SOURCE
#define TRACEPOINT_DEFINE
#define TRACEPOINT_CREATE_PROBES
#include "lttng_ust_python.h"

/*
 * The tracepoint fired by the agent.
 */

void py_tracepoint(const char *asctime, const char *msg,
		const char *logger_name, const char *funcName, unsigned int lineno,
		unsigned int int_loglevel, unsigned int thread, const char *threadName)
{
	tracepoint(lttng_python, event, asctime, msg, logger_name, funcName,
			lineno, int_loglevel, thread, threadName);
}
