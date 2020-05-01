/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright 2011 Lai Jiangshan <laijs@cn.fujitsu.com>
 *
 * mmap/reservation based memory management for Lock-Free RCU Hash Table
 */

#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>
#include "rculfhash-internal.h"

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS		MAP_ANON
#endif

/*
 * The allocation scheme used by the mmap based RCU hash table is to make a
 * large unaccessible mapping to reserve memory without allocating it.
 * Then smaller chunks are allocated by overlapping read/write mappings which
 * do allocate memory. Deallocation is done by an overlapping unaccessible
 * mapping.
 *
 * This scheme was tested on Linux, macOS and Solaris. However, on Cygwin the
 * mmap wrapper is based on the Windows NtMapViewOfSection API which doesn't
 * support overlapping mappings.
 *
 * An alternative to the overlapping mappings is to use mprotect to change the
 * protection on chunks of the large mapping, read/write to allocate and none
 * to deallocate. This works perfecty on Cygwin and Solaris but on Linux a
 * call to madvise is also required to deallocate and it just doesn't work on
 * macOS.
 *
 * For this reason, we keep to original scheme on all platforms except Cygwin.
 */


/* Reserve inaccessible memory space without allocating it */
static
void *memory_map(size_t length)
{
	void *ret;

	ret = mmap(NULL, length, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (ret == MAP_FAILED) {
		perror("mmap");
		abort();
	}
	return ret;
}

static
void memory_unmap(void *ptr, size_t length)
{
	if (munmap(ptr, length)) {
		perror("munmap");
		abort();
	}
}

#ifdef __CYGWIN__
/* Set protection to read/write to allocate a memory chunk */
static
void memory_populate(void *ptr, size_t length)
{
	if (mprotect(ptr, length, PROT_READ | PROT_WRITE)) {
		perror("mprotect");
		abort();
	}
}

/* Set protection to none to deallocate a memory chunk */
static
void memory_discard(void *ptr, size_t length)
{
	if (mprotect(ptr, length, PROT_NONE)) {
		perror("mprotect");
		abort();
	}
}

#else /* __CYGWIN__ */

static
void memory_populate(void *ptr, size_t length)
{
	if (mmap(ptr, length, PROT_READ | PROT_WRITE,
			MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
			-1, 0) != ptr) {
		perror("mmap");
		abort();
	}
}

/*
 * Discard garbage memory and avoid system save it when try to swap it out.
 * Make it still reserved, inaccessible.
 */
static
void memory_discard(void *ptr, size_t length)
{
	if (mmap(ptr, length, PROT_NONE,
			MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
			-1, 0) != ptr) {
		perror("mmap");
		abort();
	}
}
#endif /* __CYGWIN__ */

static
void lttng_ust_lfht_alloc_bucket_table(struct lttng_ust_lfht *ht, unsigned long order)
{
	if (order == 0) {
		if (ht->min_nr_alloc_buckets == ht->max_nr_buckets) {
			/* small table */
			ht->tbl_mmap = calloc(ht->max_nr_buckets,
					sizeof(*ht->tbl_mmap));
			assert(ht->tbl_mmap);
			return;
		}
		/* large table */
		ht->tbl_mmap = memory_map(ht->max_nr_buckets
			* sizeof(*ht->tbl_mmap));
		memory_populate(ht->tbl_mmap,
			ht->min_nr_alloc_buckets * sizeof(*ht->tbl_mmap));
	} else if (order > ht->min_alloc_buckets_order) {
		/* large table */
		unsigned long len = 1UL << (order - 1);

		assert(ht->min_nr_alloc_buckets < ht->max_nr_buckets);
		memory_populate(ht->tbl_mmap + len,
				len * sizeof(*ht->tbl_mmap));
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
	if (order == 0) {
		if (ht->min_nr_alloc_buckets == ht->max_nr_buckets) {
			/* small table */
			poison_free(ht->tbl_mmap);
			return;
		}
		/* large table */
		memory_unmap(ht->tbl_mmap,
			ht->max_nr_buckets * sizeof(*ht->tbl_mmap));
	} else if (order > ht->min_alloc_buckets_order) {
		/* large table */
		unsigned long len = 1UL << (order - 1);

		assert(ht->min_nr_alloc_buckets < ht->max_nr_buckets);
		memory_discard(ht->tbl_mmap + len, len * sizeof(*ht->tbl_mmap));
	}
	/* Nothing to do for 0 < order && order <= ht->min_alloc_buckets_order */
}

static
struct lttng_ust_lfht_node *bucket_at(struct lttng_ust_lfht *ht, unsigned long index)
{
	return &ht->tbl_mmap[index];
}

static
struct lttng_ust_lfht *alloc_lttng_ust_lfht(unsigned long min_nr_alloc_buckets,
		unsigned long max_nr_buckets)
{
	unsigned long page_bucket_size;

	page_bucket_size = getpagesize() / sizeof(struct lttng_ust_lfht_node);
	if (max_nr_buckets <= page_bucket_size) {
		/* small table */
		min_nr_alloc_buckets = max_nr_buckets;
	} else {
		/* large table */
		min_nr_alloc_buckets = max(min_nr_alloc_buckets,
					page_bucket_size);
	}

	return __default_alloc_lttng_ust_lfht(
			&lttng_ust_lfht_mm_mmap, sizeof(struct lttng_ust_lfht),
			min_nr_alloc_buckets, max_nr_buckets);
}

const struct lttng_ust_lfht_mm_type lttng_ust_lfht_mm_mmap = {
	.alloc_lttng_ust_lfht = alloc_lttng_ust_lfht,
	.alloc_bucket_table = lttng_ust_lfht_alloc_bucket_table,
	.free_bucket_table = lttng_ust_lfht_free_bucket_table,
	.bucket_at = bucket_at,
};
