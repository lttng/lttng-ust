/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright 2011 Lai Jiangshan <laijs@cn.fujitsu.com>
 *
 * Chunk based memory management for Lock-Free RCU Hash Table
 */

#include <stddef.h>
#include "rculfhash-internal.h"

static
void lttng_ust_lfht_alloc_bucket_table(struct lttng_ust_lfht *ht, unsigned long order)
{
	if (order == 0) {
		ht->tbl_chunk[0] = calloc(ht->min_nr_alloc_buckets,
			sizeof(struct lttng_ust_lfht_node));
		assert(ht->tbl_chunk[0]);
	} else if (order > ht->min_alloc_buckets_order) {
		unsigned long i, len = 1UL << (order - 1 - ht->min_alloc_buckets_order);

		for (i = len; i < 2 * len; i++) {
			ht->tbl_chunk[i] = calloc(ht->min_nr_alloc_buckets,
				sizeof(struct lttng_ust_lfht_node));
			assert(ht->tbl_chunk[i]);
		}
	}
	/* Nothing to do for 0 < order && order <= ht->min_alloc_buckets_order */
}

/*
 * lttng_ust_lfht_free_bucket_table() should be called with decreasing order.
 * When lttng_ust_lfht_free_bucket_table(0) is called, it means the whole
 * lfht is destroyed.
 */
static
void lttng_ust_lfht_free_bucket_table(struct lttng_ust_lfht *ht, unsigned long order)
{
	if (order == 0)
		poison_free(ht->tbl_chunk[0]);
	else if (order > ht->min_alloc_buckets_order) {
		unsigned long i, len = 1UL << (order - 1 - ht->min_alloc_buckets_order);

		for (i = len; i < 2 * len; i++)
			poison_free(ht->tbl_chunk[i]);
	}
	/* Nothing to do for 0 < order && order <= ht->min_alloc_buckets_order */
}

static
struct lttng_ust_lfht_node *bucket_at(struct lttng_ust_lfht *ht, unsigned long index)
{
	unsigned long chunk, offset;

	chunk = index >> ht->min_alloc_buckets_order;
	offset = index & (ht->min_nr_alloc_buckets - 1);
	return &ht->tbl_chunk[chunk][offset];
}

static
struct lttng_ust_lfht *alloc_lttng_ust_lfht(unsigned long min_nr_alloc_buckets,
		unsigned long max_nr_buckets)
{
	unsigned long nr_chunks, lttng_ust_lfht_size;

	min_nr_alloc_buckets = max(min_nr_alloc_buckets,
				max_nr_buckets / MAX_CHUNK_TABLE);
	nr_chunks = max_nr_buckets / min_nr_alloc_buckets;
	lttng_ust_lfht_size = offsetof(struct lttng_ust_lfht, tbl_chunk) +
			sizeof(struct lttng_ust_lfht_node *) * nr_chunks;
	lttng_ust_lfht_size = max(lttng_ust_lfht_size, sizeof(struct lttng_ust_lfht));

	return __default_alloc_lttng_ust_lfht(
			&lttng_ust_lfht_mm_chunk, lttng_ust_lfht_size,
			min_nr_alloc_buckets, max_nr_buckets);
}

const struct lttng_ust_lfht_mm_type lttng_ust_lfht_mm_chunk = {
	.alloc_lttng_ust_lfht = alloc_lttng_ust_lfht,
	.alloc_bucket_table = lttng_ust_lfht_alloc_bucket_table,
	.free_bucket_table = lttng_ust_lfht_free_bucket_table,
	.bucket_at = bucket_at,
};
