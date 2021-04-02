/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng Bitmap API
 */

#ifndef _UST_COMMON_BITMAP_H
#define _UST_COMMON_BITMAP_H

#include <urcu/compiler.h>
#include <urcu/system.h>
#include <urcu/uatomic.h>
#include <stdbool.h>

static inline void lttng_bitmap_index(unsigned int index, unsigned int *word,
		unsigned int *bit)
{
	*word = index / CAA_BITS_PER_LONG;
	*bit = index % CAA_BITS_PER_LONG;
}

static inline void lttng_bitmap_set_bit(unsigned int index, unsigned long *p)
{
	unsigned int word, bit;
	unsigned long val;

	lttng_bitmap_index(index, &word, &bit);
	val = 1U << bit;
	uatomic_or(p + word, val);
}

static inline void lttng_bitmap_clear_bit(unsigned int index, unsigned long *p)
{
	unsigned int word, bit;
	unsigned long val;

	lttng_bitmap_index(index, &word, &bit);
	val = ~(1U << bit);
	uatomic_and(p + word, val);
}

static inline bool lttng_bitmap_test_bit(unsigned int index, unsigned long *p)
{
	unsigned int word, bit;

	lttng_bitmap_index(index, &word, &bit);
	return (CMM_LOAD_SHARED(p[word]) >> bit) & 0x1;
}

#endif /* _UST_COMMON_BITMAP_H */
