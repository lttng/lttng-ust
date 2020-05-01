/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright 2011 Lai Jiangshan <laijs@cn.fujitsu.com>
 *
 * Order based memory management for Lock-Free RCU Hash Table
 */

#include <rculfhash-internal.h>

static
void lttng_ust_lfht_alloc_bucket_table(struct lttng_ust_lfht *ht, unsigned long order)
{
	if (order == 0) {
		ht->tbl_order[0] = calloc(ht->min_nr_alloc_buckets,
			sizeof(struct lttng_ust_lfht_node));
		assert(ht->tbl_order[0]);
	} else if (order > ht->min_alloc_buckets_order) {
		ht->tbl_order[order] = calloc(1UL << (order -1),
			sizeof(struct lttng_ust_lfht_node));
		assert(ht->tbl_order[order]);
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
		poison_free(ht->tbl_order[0]);
	else if (order > ht->min_alloc_buckets_order)
		poison_free(ht->tbl_order[order]);
	/* Nothing to do for 0 < order && order <= ht->min_alloc_buckets_order */
}

static
struct lttng_ust_lfht_node *bucket_at(struct lttng_ust_lfht *ht, unsigned long index)
{
	unsigned long order;

	if (index < ht->min_nr_alloc_buckets) {
		dbg_printf("bucket index %lu order 0 aridx 0\n", index);
		return &ht->tbl_order[0][index];
	}
	/*
	 * equivalent to lttng_ust_lfht_get_count_order_ulong(index + 1), but
	 * optimizes away the non-existing 0 special-case for
	 * lttng_ust_lfht_get_count_order_ulong.
	 */
	order = lttng_ust_lfht_fls_ulong(index);
	dbg_printf("bucket index %lu order %lu aridx %lu\n",
		   index, order, index & ((1UL << (order - 1)) - 1));
	return &ht->tbl_order[order][index & ((1UL << (order - 1)) - 1)];
}

static
struct lttng_ust_lfht *alloc_lttng_ust_lfht(unsigned long min_nr_alloc_buckets,
		unsigned long max_nr_buckets)
{
	return __default_alloc_lttng_ust_lfht(
			&lttng_ust_lfht_mm_order, sizeof(struct lttng_ust_lfht),
			min_nr_alloc_buckets, max_nr_buckets);
}

const struct lttng_ust_lfht_mm_type lttng_ust_lfht_mm_order = {
	.alloc_lttng_ust_lfht = alloc_lttng_ust_lfht,
	.alloc_bucket_table = lttng_ust_lfht_alloc_bucket_table,
	.free_bucket_table = lttng_ust_lfht_free_bucket_table,
	.bucket_at = bucket_at,
};
