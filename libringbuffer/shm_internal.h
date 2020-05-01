/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _LIBRINGBUFFER_SHM_INTERNAL_H
#define _LIBRINGBUFFER_SHM_INTERNAL_H

struct shm_ref {
	volatile ssize_t index;		/* within the object table */
	volatile ssize_t offset;	/* within the object */
};

#define DECLARE_SHMP(type, name)	\
	union {				\
		struct shm_ref _ref;	\
		type *_type;		\
	} name

#endif /* _LIBRINGBUFFER_SHM_INTERNAL_H */
