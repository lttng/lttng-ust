#ifndef LTTNG_UST_GETCPU_H
#define LTTNG_UST_GETCPU_H

/*
 * Copyright (C) 2014  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; version 2.1 of
 * the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <stdint.h>
#include <stddef.h>

/*
 * Set getcpu override read callback. This callback should return the
 * current CPU number.
 */
int lttng_ust_getcpu_override(int (*getcpu)(void));

#endif /* LTTNG_UST_GETCPU_H */
