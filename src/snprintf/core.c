/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include "common/logging.h"

volatile enum ust_err_loglevel ust_err_loglevel;

void ust_err_init(void)
{
	char *ust_debug;

	if (ust_err_loglevel == UST_ERR_LOGLEVEL_UNKNOWN) {
		/*
		 * This getenv is not part of lttng_ust_getenv() because it
		 * is required to print ERR() performed during getenv
		 * initialization.
		 */
		ust_debug = getenv("LTTNG_UST_DEBUG");
		if (ust_debug)
			ust_err_loglevel = UST_ERR_LOGLEVEL_DEBUG;
		else
			ust_err_loglevel = UST_ERR_LOGLEVEL_NORMAL;
	}
}
