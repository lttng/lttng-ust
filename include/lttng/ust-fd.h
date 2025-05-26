/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _LTTNG_UST_FD_H
#define _LTTNG_UST_FD_H

/*
 * These symbols are provided by 'liblttng-ust-common'.
 */

#include <stdio.h>

int lttng_ust_add_fd_to_tracker(int fd);
void lttng_ust_delete_fd_from_tracker(int fd);
void lttng_ust_lock_fd_tracker(void);
void lttng_ust_unlock_fd_tracker(void);

int lttng_ust_safe_close_fd(int fd, int (*close_cb)(int));
int lttng_ust_safe_fclose_stream(FILE *stream, int (*fclose_cb)(FILE *stream));
int lttng_ust_safe_closefrom_fd(int lowfd, int (*close_cb)(int));
int lttng_ust_safe_close_range_fd(unsigned int first, unsigned int last, int flags,
		int (*close_range_cb)(unsigned int, unsigned int, int));

#endif	/* _LTTNG_UST_FD_H */
