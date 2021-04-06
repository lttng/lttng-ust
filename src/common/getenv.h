/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2015 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _UST_COMMON_GETENV_H
#define _UST_COMMON_GETENV_H

/*
 * Always add the lttng-ust environment variables using the lttng_ust_getenv()
 * infrastructure rather than using getenv() directly.  This ensures that we
 * don't trigger races between getenv() invoked by lttng-ust listener threads
 * invoked concurrently with setenv() called by an otherwise single-threaded
 * application thread. (the application is not aware that it runs with
 * lttng-ust)
 */

char *lttng_ust_getenv(const char *name)
	__attribute__((visibility("hidden")));


/*
 * Initialize the internal filtered list of environment variables.
 */
void lttng_ust_getenv_init(void)
	__attribute__((visibility("hidden")));

#endif /* _UST_COMMON_GETENV_H */
