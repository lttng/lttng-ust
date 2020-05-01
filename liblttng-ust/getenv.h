/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2015 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _COMPAT_GETENV_H
#define _COMPAT_GETENV_H

/*
 * Always add the lttng-ust environment variables to lttng_getenv()
 * infrastructure rather than using getenv() directly from lttng-ust.
 * This ensures that we don't trigger races between getenv() invoked by
 * lttng-ust listener threads invoked concurrently with setenv() called
 * by an otherwise single-threaded application thread. (the application
 * is not aware that it runs with lttng-ust)
 */

char *lttng_getenv(const char *name);

void lttng_ust_getenv_init(void);

#endif /* _COMPAT_GETENV_H */
