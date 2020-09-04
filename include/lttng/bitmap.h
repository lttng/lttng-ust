/*
 * lttng/bitmap.h
 *
 * LTTng Bitmap API
 *
 * Copyright (C) 2020 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _LTTNG_BITMAP_H
#define _LTTNG_BITMAP_H

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

#endif /* _LTTNG_BITMAP_H */
