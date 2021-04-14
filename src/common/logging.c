/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include <urcu/compiler.h>
#include <urcu/system.h>

#include "common/logging.h"

int lttng_ust_log_level = LTTNG_UST_LOG_LEVEL_UNKNOWN;

/*
 * Initialize the global log level from the "LTTNG_UST_DEBUG" environment
 * variable.
 *
 * This could end up being called concurently by multiple threads but doesn't
 * require a mutex since the input is invariant across threads and the result
 * will be the same.
 *
 * Return the current log level to save the caller a second read of the global
 * log level.
 */
int lttng_ust_logging_init(void)
{
	char *lttng_ust_debug;
	int current_log_level;

	current_log_level = CMM_LOAD_SHARED(lttng_ust_log_level);

	/*
	 * Check early if we are initialized, this is unlikely as it's already tested
	 * in lttng_ust_debug_enabled before performing lazy initialization.
	 */
	if (caa_unlikely(current_log_level != LTTNG_UST_LOG_LEVEL_UNKNOWN))
		goto end;

	/*
	 * This getenv is not part of lttng_ust_getenv() because logging is
	 * used in the getenv initialization and thus logging must be
	 * initialized prior to getenv.
	 */
	lttng_ust_debug = getenv("LTTNG_UST_DEBUG");

	/*
	 * If the LTTNG_UST_DEBUG environment variable is defined, print all
	 * messages, otherwise print nothing.
	 */
	if (lttng_ust_debug)
		current_log_level = LTTNG_UST_LOG_LEVEL_DEBUG;
	else
		current_log_level = LTTNG_UST_LOG_LEVEL_SILENT;

	/* Initialize the log level */
	CMM_STORE_SHARED(lttng_ust_log_level, current_log_level);

end:
	return current_log_level;
}
