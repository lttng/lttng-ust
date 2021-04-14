/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2021 Michael Jeanson <mjeanson@efficios.com>
 */

#include "common/logging.h"
#include "common/ust-fd.h"

static
void lttng_ust_common_init(void)
	__attribute__((constructor));
static
void lttng_ust_common_init(void)
{
	/*
	 * Initialize the fd-tracker, other libraries using it should also call
	 * this in their constructor in case it gets executed before this one.
	 */
	lttng_ust_init_fd_tracker();
}
