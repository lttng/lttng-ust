#ifndef _LIBRINGBUFFER_SHM_INTERNAL_H
#define _LIBRINGBUFFER_SHM_INTERNAL_H

/*
 * libringbuffer/shm_internal.h
 *
 * Copyright 2011 (c) - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Dual LGPL v2.1/GPL v2 license.
 */

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
