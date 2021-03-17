/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2010-2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _LTTNG_ALIGN_H
#define _LTTNG_ALIGN_H

#include <lttng/ust-bug.h>

/**
 * lttng_ust_offset_align - Calculate the offset needed to align an object on
 *                its natural alignment towards higher addresses.
 * @align_drift:  object offset from an "alignment"-aligned address.
 * @alignment:    natural object alignment. Must be non-zero, power of 2.
 *
 * Returns the offset that must be added to align towards higher
 * addresses.
 */
#define lttng_ust_offset_align(align_drift, alignment)			       \
	({								       \
		LTTNG_BUILD_RUNTIME_BUG_ON((alignment) == 0		       \
				   || ((alignment) & ((alignment) - 1)));      \
		(((alignment) - (align_drift)) & ((alignment) - 1));	       \
	})

/**
 * lttng_ust_offset_align_floor - Calculate the offset needed to align an
 *                object on its natural alignment towards lower addresses.
 * @align_drift:  object offset from an "alignment"-aligned address.
 * @alignment:    natural object alignment. Must be non-zero, power of 2.
 *
 * Returns the offset that must be substracted to align towards lower addresses.
 */
#define lttng_ust_offset_align_floor(align_drift, alignment)		       \
	({								       \
		LTTNG_BUILD_RUNTIME_BUG_ON((alignment) == 0		       \
				   || ((alignment) & ((alignment) - 1)));      \
		(((align_drift) - (alignment)) & ((alignment) - 1));	       \
	})

#endif /* _LTTNG_ALIGN_H */
