/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright 2011 Lai Jiangshan <laijs@cn.fujitsu.com>
 *
 * Internal header for Lock-Free RCU Hash Table
 */

#ifndef _LTTNG_UST_RCULFHASH_INTERNAL_H
#define _LTTNG_UST_RCULFHASH_INTERNAL_H

#include "rculfhash.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#ifdef DEBUG
#define dbg_printf(fmt, args...)     printf("[debug lttng-ust rculfhash] " fmt, ## args)
#else
#define dbg_printf(fmt, args...)				\
do {								\
	/* do nothing but check printf format */		\
	if (0)							\
		printf("[debug lttng-ust rculfhash] " fmt, ## args);	\
} while (0)
#endif

#if (CAA_BITS_PER_LONG == 32)
#define MAX_TABLE_ORDER			32
#else
#define MAX_TABLE_ORDER			64
#endif

#define MAX_CHUNK_TABLE			(1UL << 10)

#ifndef min
#define min(a, b)	((a) < (b) ? (a) : (b))
#endif

#ifndef max
#define max(a, b)	((a) > (b) ? (a) : (b))
#endif

/*
 * lttng_ust_lfht: Top-level data structure representing a lock-free hash
 * table. Defined in the implementation file to make it be an opaque
 * cookie to users.
 *
 * The fields used in fast-paths are placed near the end of the
 * structure, because we need to have a variable-sized union to contain
 * the mm plugin fields, which are used in the fast path.
 */
struct lttng_ust_lfht {
	/* Initial configuration items */
	unsigned long max_nr_buckets;
	const struct lttng_ust_lfht_mm_type *mm;	/* memory management plugin */
	const struct rcu_flavor_struct *flavor;	/* RCU flavor */

	/*
	 * We need to put the work threads offline (QSBR) when taking this
	 * mutex, because we use synchronize_rcu within this mutex critical
	 * section, which waits on read-side critical sections, and could
	 * therefore cause grace-period deadlock if we hold off RCU G.P.
	 * completion.
	 */
	pthread_mutex_t resize_mutex;	/* resize mutex: add/del mutex */
	unsigned int in_progress_destroy;
	unsigned long resize_target;
	int resize_initiated;

	/*
	 * Variables needed for add and remove fast-paths.
	 */
	int flags;
	unsigned long min_alloc_buckets_order;
	unsigned long min_nr_alloc_buckets;

	/*
	 * Variables needed for the lookup, add and remove fast-paths.
	 */
	unsigned long size;	/* always a power of 2, shared (RCU) */
	/*
	 * bucket_at pointer is kept here to skip the extra level of
	 * dereference needed to get to "mm" (this is a fast-path).
	 */
	struct lttng_ust_lfht_node *(*bucket_at)(struct lttng_ust_lfht *ht,
			unsigned long index);
	/*
	 * Dynamic length "tbl_chunk" needs to be at the end of
	 * lttng_ust_lfht.
	 */
	union {
		/*
		 * Contains the per order-index-level bucket node table.
		 * The size of each bucket node table is half the number
		 * of hashes contained in this order (except for order 0).
		 * The minimum allocation buckets size parameter allows
		 * combining the bucket node arrays of the lowermost
		 * levels to improve cache locality for small index orders.
		 */
		struct lttng_ust_lfht_node *tbl_order[MAX_TABLE_ORDER];

		/*
		 * Contains the bucket node chunks. The size of each
		 * bucket node chunk is ->min_alloc_size (we avoid to
		 * allocate chunks with different size). Chunks improve
		 * cache locality for small index orders, and are more
		 * friendly with environments where allocation of large
		 * contiguous memory areas is challenging due to memory
		 * fragmentation concerns or inability to use virtual
		 * memory addressing.
		 */
		struct lttng_ust_lfht_node *tbl_chunk[0];

		/*
		 * Memory mapping with room for all possible buckets.
		 * Their memory is allocated when needed.
		 */
		struct lttng_ust_lfht_node *tbl_mmap;
	};
	/*
	 * End of variables needed for the lookup, add and remove
	 * fast-paths.
	 */
};

extern unsigned int lttng_ust_lfht_fls_ulong(unsigned long x)
	__attribute__((visibility("hidden")));

extern int lttng_ust_lfht_get_count_order_u32(uint32_t x)
	__attribute__((visibility("hidden")));

extern int lttng_ust_lfht_get_count_order_ulong(unsigned long x)
	__attribute__((visibility("hidden")));

#ifdef POISON_FREE
#define poison_free(ptr)					\
	do {							\
		if (ptr) {					\
			memset(ptr, 0x42, sizeof(*(ptr)));	\
			free(ptr);				\
		}						\
	} while (0)
#else
#define poison_free(ptr)	free(ptr)
#endif

static inline
struct lttng_ust_lfht *__default_alloc_lttng_ust_lfht(
		const struct lttng_ust_lfht_mm_type *mm,
		unsigned long lttng_ust_lfht_size,
		unsigned long min_nr_alloc_buckets,
		unsigned long max_nr_buckets)
{
	struct lttng_ust_lfht *ht;

	ht = calloc(1, lttng_ust_lfht_size);
	assert(ht);

	ht->mm = mm;
	ht->bucket_at = mm->bucket_at;
	ht->min_nr_alloc_buckets = min_nr_alloc_buckets;
	ht->min_alloc_buckets_order =
		lttng_ust_lfht_get_count_order_ulong(min_nr_alloc_buckets);
	ht->max_nr_buckets = max_nr_buckets;

	return ht;
}

#endif /* _LTTNG_UST_RCULFHASH_INTERNAL_H */
