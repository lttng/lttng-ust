#ifndef _LTTNG_ERROR_H
#define _LTTNG_ERROR_H

/*
 * Copyright (c) 2011 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <urcu/compiler.h>
#include <unistd.h>

#define MAX_ERRNO	4095

static inline
int IS_ERR_VALUE(long value)
{
	if (caa_unlikely((unsigned long) value >= (unsigned long) -MAX_ERRNO))
		return 1;
	else
		return 0;
}

static inline
void *ERR_PTR(long error)
{
	return (void *) error;
}

static inline
long PTR_ERR(const void *ptr)
{
	return (long) ptr;
}

static inline
int IS_ERR(const void *ptr)
{
	return IS_ERR_VALUE((long) ptr);
}

#endif /* _LTTNG_ERROR_H */
