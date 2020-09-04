#ifndef _LIBCOUNTER_SHM_INTERNAL_H
#define _LIBCOUNTER_SHM_INTERNAL_H

/*
 * libcounter/shm_internal.h
 *
 * Copyright (C) 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

struct lttng_counter_shm_ref {
	volatile ssize_t index;		/* within the object table */
	volatile ssize_t offset;	/* within the object */
};

#define DECLARE_LTTNG_COUNTER_SHMP(type, name)		\
	union {						\
		struct lttng_counter_shm_ref _ref;	\
		type *_type;				\
	} name

#endif /* _LIBCOUNTER_SHM_INTERNAL_H */
