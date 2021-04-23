/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2021 Michael Jeanson <mjeanson@efficios.com>
 */

#ifndef _LTTNG_UST_COMMON_FD_TRACKER_H
#define _LTTNG_UST_COMMON_FD_TRACKER_H

void lttng_ust_fd_tracker_init(void)
	__attribute__((visibility("hidden")));

void lttng_ust_fd_tracker_alloc_tls(void)
	__attribute__((visibility("hidden")));

#endif
