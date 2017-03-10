#ifndef _COMPAT_GETENV_H
#define _COMPAT_GETENV_H

/*
 * Copyright (C) 2015 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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
 * Always add the lttng-ust environment variables to lttng_getenv()
 * infrastructure rather than using getenv() directly from lttng-ust.
 * This ensures that we don't trigger races between getenv() invoked by
 * lttng-ust listener threads invoked concurrently with setenv() called
 * by an otherwise single-threaded application thread. (the application
 * is not aware that it runs with lttng-ust)
 */

char *lttng_getenv(const char *name);

void lttng_ust_getenv_init(void);

#endif /* _COMPAT_GETENV_H */
