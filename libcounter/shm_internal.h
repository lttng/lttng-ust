/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _LIBCOUNTER_SHM_INTERNAL_H
#define _LIBCOUNTER_SHM_INTERNAL_H

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
