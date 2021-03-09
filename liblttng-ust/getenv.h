/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2015 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _COMPAT_GETENV_H
#define _COMPAT_GETENV_H

#include "ust-helper.h"

/*
 * Always add the lttng-ust environment variables using the lttng_ust_getenv()
 * infrastructure rather than using getenv() directly.  This ensures that we
 * don't trigger races between getenv() invoked by lttng-ust listener threads
 * invoked concurrently with setenv() called by an otherwise single-threaded
 * application thread. (the application is not aware that it runs with
 * lttng-ust)
 */

LTTNG_HIDDEN
char *lttng_ust_getenv(const char *name);

LTTNG_HIDDEN
void lttng_ust_getenv_init(void);

#endif /* _COMPAT_GETENV_H */
