/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include <usterr-signal-safe.h>

volatile enum ust_loglevel ust_loglevel;

void init_usterr(void)
{
	char *ust_debug;

	if (ust_loglevel == UST_LOGLEVEL_UNKNOWN) {
		/*
		 * This getenv is not part of lttng_getenv() because it
		 * is required to print ERR() performed during getenv
		 * initialization.
		 */
		ust_debug = getenv("LTTNG_UST_DEBUG");
		if (ust_debug)
			ust_loglevel = UST_LOGLEVEL_DEBUG;
		else
			ust_loglevel = UST_LOGLEVEL_NORMAL;
	}
}
