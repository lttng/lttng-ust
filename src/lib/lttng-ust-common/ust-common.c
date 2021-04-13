/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2021 Michael Jeanson <mjeanson@efficios.com>
 */

#include <lttng/ust-common.h>

#include "common/logging.h"
#include "common/ust-fd.h"
#include "common/getenv.h"

#include "lib/lttng-ust-common/fd-tracker.h"

/*
 * The liblttng-ust-common constructor, initialize the internal shared state.
 * Libraries linking on liblttng-ust-common should also call this early in
 * their constructor since there is no reliable way to guarantee the execution
 * order of constructors across shared library.
 */
void lttng_ust_common_ctor(void)
{
	/*
	 * Initialize the shared state of the fd tracker.
	 */
	lttng_ust_fd_tracker_init();
}
