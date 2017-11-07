#ifndef _LTTNG_UST_FD_H
#define _LTTNG_UST_FD_H

/*
 * Copyright (C) 2016 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; only
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/*
 * This header is meant for liblttng and libust internal use ONLY.
 * These declarations should NOT be considered stable API.
 */

#include <stdio.h>

void lttng_ust_init_fd_tracker(void);
void lttng_ust_add_fd_to_tracker(int fd);
void lttng_ust_delete_fd_from_tracker(int fd);
void lttng_ust_lock_fd_tracker(void);
void lttng_ust_unlock_fd_tracker(void);

int lttng_ust_safe_close_fd(int fd, int (*close_cb)(int));
int lttng_ust_safe_fclose_stream(FILE *stream, int (*fclose_cb)(FILE *stream));
int lttng_ust_safe_closefrom_fd(int lowfd, int (*close_cb)(int));

#endif	/* _LTTNG_UST_FD_H */
