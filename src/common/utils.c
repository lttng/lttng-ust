/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011 EfficiOS Inc.
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include "common/utils.h"

ssize_t lttng_ust_read(int fd, void *buf, size_t len)
{
	ssize_t ret;
	size_t copied = 0, to_copy = len;

	do {
		ret = read(fd, buf + copied, to_copy);
		if (ret > 0) {
			copied += ret;
			to_copy -= ret;
		}
	} while ((ret > 0 && to_copy > 0)
		|| (ret < 0 && errno == EINTR));
	if (ret > 0) {
		ret = copied;
	}
	return ret;
}
