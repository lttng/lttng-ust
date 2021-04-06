/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include "common/logging.h"

volatile enum lttng_ust_log_level lttng_ust_log_level;

void lttng_ust_logging_init(void)
{
	char *lttng_ust_debug;

	if (lttng_ust_log_level == LTTNG_UST_LOG_LEVEL_UNKNOWN) {
		/*
		 * This getenv is not part of lttng_ust_getenv() because it
		 * is required to print ERR() performed during getenv
		 * initialization.
		 */
		lttng_ust_debug = getenv("LTTNG_UST_DEBUG");
		if (lttng_ust_debug)
			lttng_ust_log_level = LTTNG_UST_LOG_LEVEL_DEBUG;
		else
			lttng_ust_log_level = LTTNG_UST_LOG_LEVEL_NORMAL;
	}
}
