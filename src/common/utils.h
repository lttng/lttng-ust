/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright (C) 2021 Michael Jeanson <mjeanson@efficios.com>
 */

#ifndef _UST_COMMON_UTILS_H
#define _UST_COMMON_UTILS_H

ssize_t lttng_ust_read(int fd, void *buf, size_t len)
	__attribute__((visibility("hidden")));

#endif
