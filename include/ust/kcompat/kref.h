#ifndef _KCOMPAT_KREF_H
#define _KCOMPAT_KREF_H

/*
 * Kernel sourcecode compatible reference counting implementation
 *
 * Copyright (C) 2009 Novell Inc.
 *
 * Author: Jan Blunck <jblunck@suse.de>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version 2.1 as
 * published by the Free  Software Foundation.
 */

#include <assert.h>
#include <urcu/uatomic_arch.h>

struct kref {
	long refcount; /* ATOMIC */
};

static inline void kref_set(struct kref *ref, int val)
{
	uatomic_set(&ref->refcount, val);
}

static inline void kref_init(struct kref *ref)
{
	kref_set(ref, 1);
}

static inline void kref_get(struct kref *ref)
{
	long result = uatomic_add_return(&ref->refcount, 1);
	assert(result != 0);
}

static inline void kref_put(struct kref *ref, void (*release)(struct kref *))
{
	long res = uatomic_sub_return(&ref->refcount, 1);
	if (res == 0)
		release(ref);
}

#endif /* _KCOMPAT_KREF_H */
