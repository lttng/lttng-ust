#ifndef _LTTNG_MMAP_H
#define _LTTNG_MMAP_H

/*
 * Copyright (c) 2019 - Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
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

#include <sys/mman.h>

#if defined(__linux__) && defined(MAP_POPULATE)
# define LTTNG_MAP_POPULATE MAP_POPULATE
#else
# define LTTNG_MAP_POPULATE 0
#endif /* __linux__ && MAP_POPULATE */

#endif /* _LTTNG_MMAP_H */
