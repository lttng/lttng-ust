/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _LTTNG_SHARE_H
#define _LTTNG_SHARE_H

#include <stdlib.h>
#include <sys/uio.h>

#include "helper.h"

/* Should be hidden but would break the ABI */
ssize_t patient_write(int fd, const void *buf, size_t count);
LTTNG_HIDDEN
ssize_t patient_writev(int fd, struct iovec *iov, int iovcnt);
/* Should be hidden but would break the ABI */
ssize_t patient_send(int fd, const void *buf, size_t count, int flags);

#endif /* _LTTNG_SHARE_H */
