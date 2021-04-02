/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _UST_COMMON_PATIENT_H
#define _UST_COMMON_PATIENT_H

#include <stdlib.h>
#include <sys/uio.h>

ssize_t ust_patient_write(int fd, const void *buf, size_t count)
	__attribute__((visibility("hidden")));

ssize_t ust_patient_writev(int fd, struct iovec *iov, int iovcnt)
	__attribute__((visibility("hidden")));

ssize_t ust_patient_send(int fd, const void *buf, size_t count, int flags)
	__attribute__((visibility("hidden")));

#endif /* _UST_COMMON_PATIENT_H */
