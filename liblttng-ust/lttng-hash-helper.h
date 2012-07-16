#ifndef _LTTNG_HASH_HELPER_H
#define _LTTNG_HASH_HELPER_H

/*
 * lttng-hash-helper.h
 *
 * LTTng hash table helpers.
 *
 * Copyright (C) 2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <assert.h>
#include <stdint.h>
#include <urcu/compiler.h>

/*
 * Hash function
 * Source: http://burtleburtle.net/bob/c/lookup3.c
 * Originally Public Domain
 */

#define rot(x, k) (((x) << (k)) | ((x) >> (32 - (k))))

#define mix(a, b, c) \
do { \
	a -= c; a ^= rot(c,  4); c += b; \
	b -= a; b ^= rot(a,  6); a += c; \
	c -= b; c ^= rot(b,  8); b += a; \
	a -= c; a ^= rot(c, 16); c += b; \
	b -= a; b ^= rot(a, 19); a += c; \
	c -= b; c ^= rot(b,  4); b += a; \
} while (0)

#define final(a, b, c) \
{ \
	c ^= b; c -= rot(b, 14); \
	a ^= c; a -= rot(c, 11); \
	b ^= a; b -= rot(a, 25); \
	c ^= b; c -= rot(b, 16); \
	a ^= c; a -= rot(c,  4);\
	b ^= a; b -= rot(a, 14); \
	c ^= b; c -= rot(b, 24); \
}

static inline __attribute__((unused))
uint32_t lttng_hash_u32(
	const uint32_t *k,	/* the key, an array of uint32_t values */
	size_t length,		/* the length of the key, in uint32_ts */
	uint32_t initval)	/* the previous hash, or an arbitrary value */
{
	uint32_t a, b, c;

	/* Set up the internal state */
	a = b = c = 0xdeadbeef + (((uint32_t) length) << 2) + initval;

	/*----------------------------------------- handle most of the key */
	while (length > 3) {
		a += k[0];
		b += k[1];
		c += k[2];
		mix(a, b, c);
		length -= 3;
		k += 3;
	}

	/*----------------------------------- handle the last 3 uint32_t's */
	switch (length) {	/* all the case statements fall through */
	case 3: c += k[2];
	case 2: b += k[1];
	case 1: a += k[0];
		final(a, b, c);
	case 0:			/* case 0: nothing left to add */
		break;
	}
	/*---------------------------------------------- report the result */
	return c;
}

static inline
void lttng_hashword2(
	const uint32_t *k,	/* the key, an array of uint32_t values */
	size_t length,		/* the length of the key, in uint32_ts */
	uint32_t *pc,		/* IN: seed OUT: primary hash value */
	uint32_t *pb)		/* IN: more seed OUT: secondary hash value */
{
	uint32_t a, b, c;

	/* Set up the internal state */
	a = b = c = 0xdeadbeef + ((uint32_t) (length << 2)) + *pc;
	c += *pb;

	/*----------------------------------------- handle most of the key */
	while (length > 3) {
		a += k[0];
		b += k[1];
		c += k[2];
		mix(a, b, c);
		length -= 3;
		k += 3;
	}

	/*----------------------------------- handle the last 3 uint32_t's */
	switch (length) {	/* all the case statements fall through */
	case 3: c += k[2];
	case 2: b += k[1];
	case 1: a += k[0];
		final(a, b, c);
	case 0:			/* case 0: nothing left to add */
		break;
	}
	/*---------------------------------------------- report the result */
	*pc = c;
	*pb = b;
}

#if (CAA_BITS_PER_LONG == 32)
static inline
unsigned long lttng_hash_mix(const void *_key, size_t length, unsigned long seed)
{
	unsigned int key = (unsigned int) _key;

	assert(length == sizeof(unsigned int));
	return lttng_hash_u32(&key, 1, seed);
}
#else
static inline
unsigned long lttng_hash_mix(const void *_key, size_t length, unsigned long seed)
{
	union {
		uint64_t v64;
		uint32_t v32[2];
	} v;
	union {
		uint64_t v64;
		uint32_t v32[2];
	} key;

	assert(length == sizeof(unsigned long));
	v.v64 = (uint64_t) seed;
	key.v64 = (uint64_t) _key;
	lttng_hashword2(key.v32, 2, &v.v32[0], &v.v32[1]);
	return v.v64;
}
#endif

#endif /* _LTTNG_HASH_HELPER_H */
