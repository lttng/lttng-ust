/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright 2010-2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright 2011 Lai Jiangshan <laijs@cn.fujitsu.com>
 *
 * Userspace RCU library - Lock-Free Resizable RCU Hash Table
 */

/*
 * Based on the following articles:
 * - Ori Shalev and Nir Shavit. Split-ordered lists: Lock-free
 *   extensible hash tables. J. ACM 53, 3 (May 2006), 379-405.
 * - Michael, M. M. High performance dynamic lock-free hash tables
 *   and list-based sets. In Proceedings of the fourteenth annual ACM
 *   symposium on Parallel algorithms and architectures, ACM Press,
 *   (2002), 73-82.
 *
 * Some specificities of this Lock-Free Resizable RCU Hash Table
 * implementation:
 *
 * - RCU read-side critical section allows readers to perform hash
 *   table lookups, as well as traversals, and use the returned objects
 *   safely by allowing memory reclaim to take place only after a grace
 *   period.
 * - Add and remove operations are lock-free, and do not need to
 *   allocate memory. They need to be executed within RCU read-side
 *   critical section to ensure the objects they read are valid and to
 *   deal with the cmpxchg ABA problem.
 * - add and add_unique operations are supported. add_unique checks if
 *   the node key already exists in the hash table. It ensures not to
 *   populate a duplicate key if the node key already exists in the hash
 *   table.
 * - The resize operation executes concurrently with
 *   add/add_unique/add_replace/remove/lookup/traversal.
 * - Hash table nodes are contained within a split-ordered list. This
 *   list is ordered by incrementing reversed-bits-hash value.
 * - An index of bucket nodes is kept. These bucket nodes are the hash
 *   table "buckets". These buckets are internal nodes that allow to
 *   perform a fast hash lookup, similarly to a skip list. These
 *   buckets are chained together in the split-ordered list, which
 *   allows recursive expansion by inserting new buckets between the
 *   existing buckets. The split-ordered list allows adding new buckets
 *   between existing buckets as the table needs to grow.
 * - The resize operation for small tables only allows expanding the
 *   hash table. It is triggered automatically by detecting long chains
 *   in the add operation.
 * - The resize operation for larger tables (and available through an
 *   API) allows both expanding and shrinking the hash table.
 * - Split-counters are used to keep track of the number of
 *   nodes within the hash table for automatic resize triggering.
 * - Resize operation initiated by long chain detection is executed by a
 *   worker thread, which keeps lock-freedom of add and remove.
 * - Resize operations are protected by a mutex.
 * - The removal operation is split in two parts: first, a "removed"
 *   flag is set in the next pointer within the node to remove. Then,
 *   a "garbage collection" is performed in the bucket containing the
 *   removed node (from the start of the bucket up to the removed node).
 *   All encountered nodes with "removed" flag set in their next
 *   pointers are removed from the linked-list. If the cmpxchg used for
 *   removal fails (due to concurrent garbage-collection or concurrent
 *   add), we retry from the beginning of the bucket. This ensures that
 *   the node with "removed" flag set is removed from the hash table
 *   (not visible to lookups anymore) before the RCU read-side critical
 *   section held across removal ends. Furthermore, this ensures that
 *   the node with "removed" flag set is removed from the linked-list
 *   before its memory is reclaimed. After setting the "removal" flag,
 *   only the thread which removal is the first to set the "removal
 *   owner" flag (with an xchg) into a node's next pointer is considered
 *   to have succeeded its removal (and thus owns the node to reclaim).
 *   Because we garbage-collect starting from an invariant node (the
 *   start-of-bucket bucket node) up to the "removed" node (or find a
 *   reverse-hash that is higher), we are sure that a successful
 *   traversal of the chain leads to a chain that is present in the
 *   linked-list (the start node is never removed) and that it does not
 *   contain the "removed" node anymore, even if concurrent delete/add
 *   operations are changing the structure of the list concurrently.
 * - The add operations perform garbage collection of buckets if they
 *   encounter nodes with removed flag set in the bucket where they want
 *   to add their new node. This ensures lock-freedom of add operation by
 *   helping the remover unlink nodes from the list rather than to wait
 *   for it do to so.
 * - There are three memory backends for the hash table buckets: the
 *   "order table", the "chunks", and the "mmap".
 * - These bucket containers contain a compact version of the hash table
 *   nodes.
 * - The RCU "order table":
 *   -  has a first level table indexed by log2(hash index) which is
 *      copied and expanded by the resize operation. This order table
 *      allows finding the "bucket node" tables.
 *   - There is one bucket node table per hash index order. The size of
 *     each bucket node table is half the number of hashes contained in
 *     this order (except for order 0).
 * - The RCU "chunks" is best suited for close interaction with a page
 *   allocator. It uses a linear array as index to "chunks" containing
 *   each the same number of buckets.
 * - The RCU "mmap" memory backend uses a single memory map to hold
 *   all buckets.
 * - synchronize_rcu is used to garbage-collect the old bucket node table.
 *
 * Ordering Guarantees:
 *
 * To discuss these guarantees, we first define "read" operation as any
 * of the the basic lttng_ust_lfht_lookup, lttng_ust_lfht_next_duplicate,
 * lttng_ust_lfht_first, lttng_ust_lfht_next operation, as well as
 * lttng_ust_lfht_add_unique (failure).
 *
 * We define "read traversal" operation as any of the following
 * group of operations
 *  - lttng_ust_lfht_lookup followed by iteration with lttng_ust_lfht_next_duplicate
 *    (and/or lttng_ust_lfht_next, although less common).
 *  - lttng_ust_lfht_add_unique (failure) followed by iteration with
 *    lttng_ust_lfht_next_duplicate (and/or lttng_ust_lfht_next, although less
 *    common).
 *  - lttng_ust_lfht_first followed iteration with lttng_ust_lfht_next (and/or
 *    lttng_ust_lfht_next_duplicate, although less common).
 *
 * We define "write" operations as any of lttng_ust_lfht_add, lttng_ust_lfht_replace,
 * lttng_ust_lfht_add_unique (success), lttng_ust_lfht_add_replace, lttng_ust_lfht_del.
 *
 * When lttng_ust_lfht_add_unique succeeds (returns the node passed as
 * parameter), it acts as a "write" operation. When lttng_ust_lfht_add_unique
 * fails (returns a node different from the one passed as parameter), it
 * acts as a "read" operation. A lttng_ust_lfht_add_unique failure is a
 * lttng_ust_lfht_lookup "read" operation, therefore, any ordering guarantee
 * referring to "lookup" imply any of "lookup" or lttng_ust_lfht_add_unique
 * (failure).
 *
 * We define "prior" and "later" node as nodes observable by reads and
 * read traversals respectively before and after a write or sequence of
 * write operations.
 *
 * Hash-table operations are often cascaded, for example, the pointer
 * returned by a lttng_ust_lfht_lookup() might be passed to a lttng_ust_lfht_next(),
 * whose return value might in turn be passed to another hash-table
 * operation. This entire cascaded series of operations must be enclosed
 * by a pair of matching rcu_read_lock() and rcu_read_unlock()
 * operations.
 *
 * The following ordering guarantees are offered by this hash table:
 *
 * A.1) "read" after "write": if there is ordering between a write and a
 *      later read, then the read is guaranteed to see the write or some
 *      later write.
 * A.2) "read traversal" after "write": given that there is dependency
 *      ordering between reads in a "read traversal", if there is
 *      ordering between a write and the first read of the traversal,
 *      then the "read traversal" is guaranteed to see the write or
 *      some later write.
 * B.1) "write" after "read": if there is ordering between a read and a
 *      later write, then the read will never see the write.
 * B.2) "write" after "read traversal": given that there is dependency
 *      ordering between reads in a "read traversal", if there is
 *      ordering between the last read of the traversal and a later
 *      write, then the "read traversal" will never see the write.
 * C)   "write" while "read traversal": if a write occurs during a "read
 *      traversal", the traversal may, or may not, see the write.
 * D.1) "write" after "write": if there is ordering between a write and
 *      a later write, then the later write is guaranteed to see the
 *      effects of the first write.
 * D.2) Concurrent "write" pairs: The system will assign an arbitrary
 *      order to any pair of concurrent conflicting writes.
 *      Non-conflicting writes (for example, to different keys) are
 *      unordered.
 * E)   If a grace period separates a "del" or "replace" operation
 *      and a subsequent operation, then that subsequent operation is
 *      guaranteed not to see the removed item.
 * F)   Uniqueness guarantee: given a hash table that does not contain
 *      duplicate items for a given key, there will only be one item in
 *      the hash table after an arbitrary sequence of add_unique and/or
 *      add_replace operations. Note, however, that a pair of
 *      concurrent read operations might well access two different items
 *      with that key.
 * G.1) If a pair of lookups for a given key are ordered (e.g. by a
 *      memory barrier), then the second lookup will return the same
 *      node as the previous lookup, or some later node.
 * G.2) A "read traversal" that starts after the end of a prior "read
 *      traversal" (ordered by memory barriers) is guaranteed to see the
 *      same nodes as the previous traversal, or some later nodes.
 * G.3) Concurrent "read" pairs: concurrent reads are unordered. For
 *      example, if a pair of reads to the same key run concurrently
 *      with an insertion of that same key, the reads remain unordered
 *      regardless of their return values. In other words, you cannot
 *      rely on the values returned by the reads to deduce ordering.
 *
 * Progress guarantees:
 *
 * * Reads are wait-free. These operations always move forward in the
 *   hash table linked list, and this list has no loop.
 * * Writes are lock-free. Any retry loop performed by a write operation
 *   is triggered by progress made within another update operation.
 *
 * Bucket node tables:
 *
 * hash table	hash table	the last	all bucket node tables
 * order	size		bucket node	0   1   2   3   4   5   6(index)
 * 				table size
 * 0		1		1		1
 * 1		2		1		1   1
 * 2		4		2		1   1   2
 * 3		8		4		1   1   2   4
 * 4		16		8		1   1   2   4   8
 * 5		32		16		1   1   2   4   8  16
 * 6		64		32		1   1   2   4   8  16  32
 *
 * When growing/shrinking, we only focus on the last bucket node table
 * which size is (!order ? 1 : (1 << (order -1))).
 *
 * Example for growing/shrinking:
 * grow hash table from order 5 to 6: init the index=6 bucket node table
 * shrink hash table from order 6 to 5: fini the index=6 bucket node table
 *
 * A bit of ascii art explanation:
 *
 * The order index is the off-by-one compared to the actual power of 2
 * because we use index 0 to deal with the 0 special-case.
 *
 * This shows the nodes for a small table ordered by reversed bits:
 *
 *    bits   reverse
 * 0  000        000
 * 4  100        001
 * 2  010        010
 * 6  110        011
 * 1  001        100
 * 5  101        101
 * 3  011        110
 * 7  111        111
 *
 * This shows the nodes in order of non-reversed bits, linked by
 * reversed-bit order.
 *
 * order              bits       reverse
 * 0               0  000        000
 * 1               |  1  001        100             <-
 * 2               |  |  2  010        010    <-     |
 *                 |  |  |  3  011        110  | <-  |
 * 3               -> |  |  |  4  100        001  |  |
 *                    -> |  |     5  101        101  |
 *                       -> |        6  110        011
 *                          ->          7  111        111
 */

/*
 * Note on port to lttng-ust: auto-resize and accounting features are
 * removed.
 */

#define _LGPL_SOURCE
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sched.h>
#include <unistd.h>

#include <lttng/ust-arch.h>
#include <lttng/urcu/pointer.h>
#include <urcu/arch.h>
#include <urcu/uatomic.h>
#include <urcu/compiler.h>
#include "rculfhash.h"
#include "rculfhash-internal.h"
#include <stdio.h>
#include <pthread.h>
#include <signal.h>

/*
 * Split-counters lazily update the global counter each 1024
 * addition/removal. It automatically keeps track of resize required.
 * We use the bucket length as indicator for need to expand for small
 * tables and machines lacking per-cpu data support.
 */
#define COUNT_COMMIT_ORDER		10

/*
 * Define the minimum table size.
 */
#define MIN_TABLE_ORDER			0
#define MIN_TABLE_SIZE			(1UL << MIN_TABLE_ORDER)

/*
 * Minimum number of bucket nodes to touch per thread to parallelize grow/shrink.
 */
#define MIN_PARTITION_PER_THREAD_ORDER	12
#define MIN_PARTITION_PER_THREAD	(1UL << MIN_PARTITION_PER_THREAD_ORDER)

/*
 * The removed flag needs to be updated atomically with the pointer.
 * It indicates that no node must attach to the node scheduled for
 * removal, and that node garbage collection must be performed.
 * The bucket flag does not require to be updated atomically with the
 * pointer, but it is added as a pointer low bit flag to save space.
 * The "removal owner" flag is used to detect which of the "del"
 * operation that has set the "removed flag" gets to return the removed
 * node to its caller. Note that the replace operation does not need to
 * iteract with the "removal owner" flag, because it validates that
 * the "removed" flag is not set before performing its cmpxchg.
 */
#define REMOVED_FLAG		(1UL << 0)
#define BUCKET_FLAG		(1UL << 1)
#define REMOVAL_OWNER_FLAG	(1UL << 2)
#define FLAGS_MASK		((1UL << 3) - 1)

/* Value of the end pointer. Should not interact with flags. */
#define END_VALUE		NULL

/*
 * ht_items_count: Split-counters counting the number of node addition
 * and removal in the table. Only used if the LTTNG_UST_LFHT_ACCOUNTING flag
 * is set at hash table creation.
 *
 * These are free-running counters, never reset to zero. They count the
 * number of add/remove, and trigger every (1 << COUNT_COMMIT_ORDER)
 * operations to update the global counter. We choose a power-of-2 value
 * for the trigger to deal with 32 or 64-bit overflow of the counter.
 */
struct ht_items_count {
	unsigned long add, del;
} __attribute__((aligned(CAA_CACHE_LINE_SIZE)));

#ifdef CONFIG_LTTNG_UST_LFHT_ITER_DEBUG

static
void lttng_ust_lfht_iter_debug_set_ht(struct lttng_ust_lfht *ht, struct lttng_ust_lfht_iter *iter)
{
	iter->lfht = ht;
}

#define lttng_ust_lfht_iter_debug_assert(...)		assert(__VA_ARGS__)

#else

static
void lttng_ust_lfht_iter_debug_set_ht(struct lttng_ust_lfht *ht __attribute__((unused)),
		struct lttng_ust_lfht_iter *iter __attribute__((unused)))
{
}

#define lttng_ust_lfht_iter_debug_assert(...)

#endif

/*
 * Algorithm to reverse bits in a word by lookup table, extended to
 * 64-bit words.
 * Source:
 * http://graphics.stanford.edu/~seander/bithacks.html#BitReverseTable
 * Originally from Public Domain.
 */

static const uint8_t BitReverseTable256[256] =
{
#define R2(n) (n),   (n) + 2*64,     (n) + 1*64,     (n) + 3*64
#define R4(n) R2(n), R2((n) + 2*16), R2((n) + 1*16), R2((n) + 3*16)
#define R6(n) R4(n), R4((n) + 2*4 ), R4((n) + 1*4 ), R4((n) + 3*4 )
	R6(0), R6(2), R6(1), R6(3)
};
#undef R2
#undef R4
#undef R6

static
uint8_t bit_reverse_u8(uint8_t v)
{
	return BitReverseTable256[v];
}

#if (CAA_BITS_PER_LONG == 32)
static
uint32_t bit_reverse_u32(uint32_t v)
{
	return ((uint32_t) bit_reverse_u8(v) << 24) |
		((uint32_t) bit_reverse_u8(v >> 8) << 16) |
		((uint32_t) bit_reverse_u8(v >> 16) << 8) |
		((uint32_t) bit_reverse_u8(v >> 24));
}
#else
static
uint64_t bit_reverse_u64(uint64_t v)
{
	return ((uint64_t) bit_reverse_u8(v) << 56) |
		((uint64_t) bit_reverse_u8(v >> 8)  << 48) |
		((uint64_t) bit_reverse_u8(v >> 16) << 40) |
		((uint64_t) bit_reverse_u8(v >> 24) << 32) |
		((uint64_t) bit_reverse_u8(v >> 32) << 24) |
		((uint64_t) bit_reverse_u8(v >> 40) << 16) |
		((uint64_t) bit_reverse_u8(v >> 48) << 8) |
		((uint64_t) bit_reverse_u8(v >> 56));
}
#endif

static
unsigned long bit_reverse_ulong(unsigned long v)
{
#if (CAA_BITS_PER_LONG == 32)
	return bit_reverse_u32(v);
#else
	return bit_reverse_u64(v);
#endif
}

/*
 * fls: returns the position of the most significant bit.
 * Returns 0 if no bit is set, else returns the position of the most
 * significant bit (from 1 to 32 on 32-bit, from 1 to 64 on 64-bit).
 */
#if defined(LTTNG_UST_ARCH_X86)
static inline
unsigned int fls_u32(uint32_t x)
{
	int r;

	__asm__ ("bsrl %1,%0\n\t"
	    "jnz 1f\n\t"
	    "movl $-1,%0\n\t"
	    "1:\n\t"
	    : "=r" (r) : "rm" (x));
	return r + 1;
}
#define HAS_FLS_U32
#endif

#if defined(LTTNG_UST_ARCH_AMD64)
static inline
unsigned int fls_u64(uint64_t x)
{
	long r;

	__asm__ ("bsrq %1,%0\n\t"
	    "jnz 1f\n\t"
	    "movq $-1,%0\n\t"
	    "1:\n\t"
	    : "=r" (r) : "rm" (x));
	return r + 1;
}
#define HAS_FLS_U64
#endif

#ifndef HAS_FLS_U64
static
unsigned int fls_u64(uint64_t x)
	__attribute__((unused));
static
unsigned int fls_u64(uint64_t x)
{
	unsigned int r = 64;

	if (!x)
		return 0;

	if (!(x & 0xFFFFFFFF00000000ULL)) {
		x <<= 32;
		r -= 32;
	}
	if (!(x & 0xFFFF000000000000ULL)) {
		x <<= 16;
		r -= 16;
	}
	if (!(x & 0xFF00000000000000ULL)) {
		x <<= 8;
		r -= 8;
	}
	if (!(x & 0xF000000000000000ULL)) {
		x <<= 4;
		r -= 4;
	}
	if (!(x & 0xC000000000000000ULL)) {
		x <<= 2;
		r -= 2;
	}
	if (!(x & 0x8000000000000000ULL)) {
		x <<= 1;
		r -= 1;
	}
	return r;
}
#endif

#ifndef HAS_FLS_U32
static
unsigned int fls_u32(uint32_t x)
	__attribute__((unused));
static
unsigned int fls_u32(uint32_t x)
{
	unsigned int r = 32;

	if (!x)
		return 0;
	if (!(x & 0xFFFF0000U)) {
		x <<= 16;
		r -= 16;
	}
	if (!(x & 0xFF000000U)) {
		x <<= 8;
		r -= 8;
	}
	if (!(x & 0xF0000000U)) {
		x <<= 4;
		r -= 4;
	}
	if (!(x & 0xC0000000U)) {
		x <<= 2;
		r -= 2;
	}
	if (!(x & 0x80000000U)) {
		x <<= 1;
		r -= 1;
	}
	return r;
}
#endif

unsigned int lttng_ust_lfht_fls_ulong(unsigned long x)
{
#if (CAA_BITS_PER_LONG == 32)
	return fls_u32(x);
#else
	return fls_u64(x);
#endif
}

/*
 * Return the minimum order for which x <= (1UL << order).
 * Return -1 if x is 0.
 */
int lttng_ust_lfht_get_count_order_u32(uint32_t x)
{
	if (!x)
		return -1;

	return fls_u32(x - 1);
}

/*
 * Return the minimum order for which x <= (1UL << order).
 * Return -1 if x is 0.
 */
int lttng_ust_lfht_get_count_order_ulong(unsigned long x)
{
	if (!x)
		return -1;

	return lttng_ust_lfht_fls_ulong(x - 1);
}

static
struct lttng_ust_lfht_node *clear_flag(struct lttng_ust_lfht_node *node)
{
	return (struct lttng_ust_lfht_node *) (((unsigned long) node) & ~FLAGS_MASK);
}

static
int is_removed(const struct lttng_ust_lfht_node *node)
{
	return ((unsigned long) node) & REMOVED_FLAG;
}

static
int is_bucket(struct lttng_ust_lfht_node *node)
{
	return ((unsigned long) node) & BUCKET_FLAG;
}

static
struct lttng_ust_lfht_node *flag_bucket(struct lttng_ust_lfht_node *node)
{
	return (struct lttng_ust_lfht_node *) (((unsigned long) node) | BUCKET_FLAG);
}

static
int is_removal_owner(struct lttng_ust_lfht_node *node)
{
	return ((unsigned long) node) & REMOVAL_OWNER_FLAG;
}

static
struct lttng_ust_lfht_node *flag_removal_owner(struct lttng_ust_lfht_node *node)
{
	return (struct lttng_ust_lfht_node *) (((unsigned long) node) | REMOVAL_OWNER_FLAG);
}

static
struct lttng_ust_lfht_node *flag_removed_or_removal_owner(struct lttng_ust_lfht_node *node)
{
	return (struct lttng_ust_lfht_node *) (((unsigned long) node) | REMOVED_FLAG | REMOVAL_OWNER_FLAG);
}

static
struct lttng_ust_lfht_node *get_end(void)
{
	return (struct lttng_ust_lfht_node *) END_VALUE;
}

static
int is_end(struct lttng_ust_lfht_node *node)
{
	return clear_flag(node) == (struct lttng_ust_lfht_node *) END_VALUE;
}

static
void lttng_ust_lfht_alloc_bucket_table(struct lttng_ust_lfht *ht, unsigned long order)
{
	return ht->mm->alloc_bucket_table(ht, order);
}

/*
 * lttng_ust_lfht_free_bucket_table() should be called with decreasing order.
 * When lttng_ust_lfht_free_bucket_table(0) is called, it means the whole
 * lfht is destroyed.
 */
static
void lttng_ust_lfht_free_bucket_table(struct lttng_ust_lfht *ht, unsigned long order)
{
	return ht->mm->free_bucket_table(ht, order);
}

static inline
struct lttng_ust_lfht_node *bucket_at(struct lttng_ust_lfht *ht, unsigned long index)
{
	return ht->bucket_at(ht, index);
}

static inline
struct lttng_ust_lfht_node *lookup_bucket(struct lttng_ust_lfht *ht, unsigned long size,
		unsigned long hash)
{
	assert(size > 0);
	return bucket_at(ht, hash & (size - 1));
}

/*
 * Remove all logically deleted nodes from a bucket up to a certain node key.
 */
static
void _lttng_ust_lfht_gc_bucket(struct lttng_ust_lfht_node *bucket, struct lttng_ust_lfht_node *node)
{
	struct lttng_ust_lfht_node *iter_prev, *iter, *next, *new_next;

	assert(!is_bucket(bucket));
	assert(!is_removed(bucket));
	assert(!is_removal_owner(bucket));
	assert(!is_bucket(node));
	assert(!is_removed(node));
	assert(!is_removal_owner(node));
	for (;;) {
		iter_prev = bucket;
		/* We can always skip the bucket node initially */
		iter = lttng_ust_rcu_dereference(iter_prev->next);
		assert(!is_removed(iter));
		assert(!is_removal_owner(iter));
		assert(iter_prev->reverse_hash <= node->reverse_hash);
		/*
		 * We should never be called with bucket (start of chain)
		 * and logically removed node (end of path compression
		 * marker) being the actual same node. This would be a
		 * bug in the algorithm implementation.
		 */
		assert(bucket != node);
		for (;;) {
			if (caa_unlikely(is_end(iter)))
				return;
			if (caa_likely(clear_flag(iter)->reverse_hash > node->reverse_hash))
				return;
			next = lttng_ust_rcu_dereference(clear_flag(iter)->next);
			if (caa_likely(is_removed(next)))
				break;
			iter_prev = clear_flag(iter);
			iter = next;
		}
		assert(!is_removed(iter));
		assert(!is_removal_owner(iter));
		if (is_bucket(iter))
			new_next = flag_bucket(clear_flag(next));
		else
			new_next = clear_flag(next);
		(void) uatomic_cmpxchg(&iter_prev->next, iter, new_next);
	}
}

static
int _lttng_ust_lfht_replace(struct lttng_ust_lfht *ht, unsigned long size,
		struct lttng_ust_lfht_node *old_node,
		struct lttng_ust_lfht_node *old_next,
		struct lttng_ust_lfht_node *new_node)
{
	struct lttng_ust_lfht_node *bucket, *ret_next;

	if (!old_node)	/* Return -ENOENT if asked to replace NULL node */
		return -ENOENT;

	assert(!is_removed(old_node));
	assert(!is_removal_owner(old_node));
	assert(!is_bucket(old_node));
	assert(!is_removed(new_node));
	assert(!is_removal_owner(new_node));
	assert(!is_bucket(new_node));
	assert(new_node != old_node);
	for (;;) {
		/* Insert after node to be replaced */
		if (is_removed(old_next)) {
			/*
			 * Too late, the old node has been removed under us
			 * between lookup and replace. Fail.
			 */
			return -ENOENT;
		}
		assert(old_next == clear_flag(old_next));
		assert(new_node != old_next);
		/*
		 * REMOVAL_OWNER flag is _NEVER_ set before the REMOVED
		 * flag. It is either set atomically at the same time
		 * (replace) or after (del).
		 */
		assert(!is_removal_owner(old_next));
		new_node->next = old_next;
		/*
		 * Here is the whole trick for lock-free replace: we add
		 * the replacement node _after_ the node we want to
		 * replace by atomically setting its next pointer at the
		 * same time we set its removal flag. Given that
		 * the lookups/get next use an iterator aware of the
		 * next pointer, they will either skip the old node due
		 * to the removal flag and see the new node, or use
		 * the old node, but will not see the new one.
		 * This is a replacement of a node with another node
		 * that has the same value: we are therefore not
		 * removing a value from the hash table. We set both the
		 * REMOVED and REMOVAL_OWNER flags atomically so we own
		 * the node after successful cmpxchg.
		 */
		ret_next = uatomic_cmpxchg(&old_node->next,
			old_next, flag_removed_or_removal_owner(new_node));
		if (ret_next == old_next)
			break;		/* We performed the replacement. */
		old_next = ret_next;
	}

	/*
	 * Ensure that the old node is not visible to readers anymore:
	 * lookup for the node, and remove it (along with any other
	 * logically removed node) if found.
	 */
	bucket = lookup_bucket(ht, size, bit_reverse_ulong(old_node->reverse_hash));
	_lttng_ust_lfht_gc_bucket(bucket, new_node);

	assert(is_removed(CMM_LOAD_SHARED(old_node->next)));
	return 0;
}

/*
 * A non-NULL unique_ret pointer uses the "add unique" (or uniquify) add
 * mode. A NULL unique_ret allows creation of duplicate keys.
 */
static
void _lttng_ust_lfht_add(struct lttng_ust_lfht *ht,
		unsigned long hash,
		lttng_ust_lfht_match_fct match,
		const void *key,
		unsigned long size,
		struct lttng_ust_lfht_node *node,
		struct lttng_ust_lfht_iter *unique_ret,
		int bucket_flag)
{
	struct lttng_ust_lfht_node *iter_prev, *iter, *next, *new_node, *new_next,
			*return_node;
	struct lttng_ust_lfht_node *bucket;

	assert(!is_bucket(node));
	assert(!is_removed(node));
	assert(!is_removal_owner(node));
	bucket = lookup_bucket(ht, size, hash);
	for (;;) {
		/*
		 * iter_prev points to the non-removed node prior to the
		 * insert location.
		 */
		iter_prev = bucket;
		/* We can always skip the bucket node initially */
		iter = lttng_ust_rcu_dereference(iter_prev->next);
		assert(iter_prev->reverse_hash <= node->reverse_hash);
		for (;;) {
			if (caa_unlikely(is_end(iter)))
				goto insert;
			if (caa_likely(clear_flag(iter)->reverse_hash > node->reverse_hash))
				goto insert;

			/* bucket node is the first node of the identical-hash-value chain */
			if (bucket_flag && clear_flag(iter)->reverse_hash == node->reverse_hash)
				goto insert;

			next = lttng_ust_rcu_dereference(clear_flag(iter)->next);
			if (caa_unlikely(is_removed(next)))
				goto gc_node;

			/* uniquely add */
			if (unique_ret
			    && !is_bucket(next)
			    && clear_flag(iter)->reverse_hash == node->reverse_hash) {
				struct lttng_ust_lfht_iter d_iter = {
					.node = node,
					.next = iter,
#ifdef CONFIG_LTTNG_UST_LFHT_ITER_DEBUG
					.lfht = ht,
#endif
				};

				/*
				 * uniquely adding inserts the node as the first
				 * node of the identical-hash-value node chain.
				 *
				 * This semantic ensures no duplicated keys
				 * should ever be observable in the table
				 * (including traversing the table node by
				 * node by forward iterations)
				 */
				lttng_ust_lfht_next_duplicate(ht, match, key, &d_iter);
				if (!d_iter.node)
					goto insert;

				*unique_ret = d_iter;
				return;
			}

			iter_prev = clear_flag(iter);
			iter = next;
		}

	insert:
		assert(node != clear_flag(iter));
		assert(!is_removed(iter_prev));
		assert(!is_removal_owner(iter_prev));
		assert(!is_removed(iter));
		assert(!is_removal_owner(iter));
		assert(iter_prev != node);
		if (!bucket_flag)
			node->next = clear_flag(iter);
		else
			node->next = flag_bucket(clear_flag(iter));
		if (is_bucket(iter))
			new_node = flag_bucket(node);
		else
			new_node = node;
		if (uatomic_cmpxchg(&iter_prev->next, iter,
				    new_node) != iter) {
			continue;	/* retry */
		} else {
			return_node = node;
			goto end;
		}

	gc_node:
		assert(!is_removed(iter));
		assert(!is_removal_owner(iter));
		if (is_bucket(iter))
			new_next = flag_bucket(clear_flag(next));
		else
			new_next = clear_flag(next);
		(void) uatomic_cmpxchg(&iter_prev->next, iter, new_next);
		/* retry */
	}
end:
	if (unique_ret) {
		unique_ret->node = return_node;
		/* unique_ret->next left unset, never used. */
	}
}

static
int _lttng_ust_lfht_del(struct lttng_ust_lfht *ht, unsigned long size,
		struct lttng_ust_lfht_node *node)
{
	struct lttng_ust_lfht_node *bucket, *next;

	if (!node)	/* Return -ENOENT if asked to delete NULL node */
		return -ENOENT;

	/* logically delete the node */
	assert(!is_bucket(node));
	assert(!is_removed(node));
	assert(!is_removal_owner(node));

	/*
	 * We are first checking if the node had previously been
	 * logically removed (this check is not atomic with setting the
	 * logical removal flag). Return -ENOENT if the node had
	 * previously been removed.
	 */
	next = CMM_LOAD_SHARED(node->next);	/* next is not dereferenced */
	if (caa_unlikely(is_removed(next)))
		return -ENOENT;
	assert(!is_bucket(next));
	/*
	 * The del operation semantic guarantees a full memory barrier
	 * before the uatomic_or atomic commit of the deletion flag.
	 */
	cmm_smp_mb__before_uatomic_or();
	/*
	 * We set the REMOVED_FLAG unconditionally. Note that there may
	 * be more than one concurrent thread setting this flag.
	 * Knowing which wins the race will be known after the garbage
	 * collection phase, stay tuned!
	 */
	uatomic_or(&node->next, REMOVED_FLAG);
	/* We performed the (logical) deletion. */

	/*
	 * Ensure that the node is not visible to readers anymore: lookup for
	 * the node, and remove it (along with any other logically removed node)
	 * if found.
	 */
	bucket = lookup_bucket(ht, size, bit_reverse_ulong(node->reverse_hash));
	_lttng_ust_lfht_gc_bucket(bucket, node);

	assert(is_removed(CMM_LOAD_SHARED(node->next)));
	/*
	 * Last phase: atomically exchange node->next with a version
	 * having "REMOVAL_OWNER_FLAG" set. If the returned node->next
	 * pointer did _not_ have "REMOVAL_OWNER_FLAG" set, we now own
	 * the node and win the removal race.
	 * It is interesting to note that all "add" paths are forbidden
	 * to change the next pointer starting from the point where the
	 * REMOVED_FLAG is set, so here using a read, followed by a
	 * xchg() suffice to guarantee that the xchg() will ever only
	 * set the "REMOVAL_OWNER_FLAG" (or change nothing if the flag
	 * was already set).
	 */
	if (!is_removal_owner(uatomic_xchg(&node->next,
			flag_removal_owner(node->next))))
		return 0;
	else
		return -ENOENT;
}

/*
 * Never called with size < 1.
 */
static
void lttng_ust_lfht_create_bucket(struct lttng_ust_lfht *ht, unsigned long size)
{
	struct lttng_ust_lfht_node *prev, *node;
	unsigned long order, len, i;
	int bucket_order;

	lttng_ust_lfht_alloc_bucket_table(ht, 0);

	dbg_printf("create bucket: order 0 index 0 hash 0\n");
	node = bucket_at(ht, 0);
	node->next = flag_bucket(get_end());
	node->reverse_hash = 0;

	bucket_order = lttng_ust_lfht_get_count_order_ulong(size);
	assert(bucket_order >= 0);

	for (order = 1; order < (unsigned long) bucket_order + 1; order++) {
		len = 1UL << (order - 1);
		lttng_ust_lfht_alloc_bucket_table(ht, order);

		for (i = 0; i < len; i++) {
			/*
			 * Now, we are trying to init the node with the
			 * hash=(len+i) (which is also a bucket with the
			 * index=(len+i)) and insert it into the hash table,
			 * so this node has to be inserted after the bucket
			 * with the index=(len+i)&(len-1)=i. And because there
			 * is no other non-bucket node nor bucket node with
			 * larger index/hash inserted, so the bucket node
			 * being inserted should be inserted directly linked
			 * after the bucket node with index=i.
			 */
			prev = bucket_at(ht, i);
			node = bucket_at(ht, len + i);

			dbg_printf("create bucket: order %lu index %lu hash %lu\n",
				   order, len + i, len + i);
			node->reverse_hash = bit_reverse_ulong(len + i);

			/* insert after prev */
			assert(is_bucket(prev->next));
			node->next = prev->next;
			prev->next = flag_bucket(node);
		}
	}
}

#if (CAA_BITS_PER_LONG > 32)
/*
 * For 64-bit architectures, with max number of buckets small enough not to
 * use the entire 64-bit memory mapping space (and allowing a fair number of
 * hash table instances), use the mmap allocator, which is faster. Otherwise,
 * fallback to the order allocator.
 */
static
const struct lttng_ust_lfht_mm_type *get_mm_type(unsigned long max_nr_buckets)
{
	if (max_nr_buckets && max_nr_buckets <= (1ULL << 32))
		return &lttng_ust_lfht_mm_mmap;
	else
		return &lttng_ust_lfht_mm_order;
}
#else
/*
 * For 32-bit architectures, use the order allocator.
 */
static
const struct lttng_ust_lfht_mm_type *get_mm_type(unsigned long max_nr_buckets __attribute__((unused)))
{
	return &lttng_ust_lfht_mm_order;
}
#endif

struct lttng_ust_lfht *lttng_ust_lfht_new(unsigned long init_size,
			unsigned long min_nr_alloc_buckets,
			unsigned long max_nr_buckets,
			int flags,
			const struct lttng_ust_lfht_mm_type *mm)
{
	struct lttng_ust_lfht *ht;
	unsigned long order;

	/* min_nr_alloc_buckets must be power of two */
	if (!min_nr_alloc_buckets || (min_nr_alloc_buckets & (min_nr_alloc_buckets - 1)))
		return NULL;

	/* init_size must be power of two */
	if (!init_size || (init_size & (init_size - 1)))
		return NULL;

	/*
	 * Memory management plugin default.
	 */
	if (!mm)
		mm = get_mm_type(max_nr_buckets);

	/* max_nr_buckets == 0 for order based mm means infinite */
	if (mm == &lttng_ust_lfht_mm_order && !max_nr_buckets)
		max_nr_buckets = 1UL << (MAX_TABLE_ORDER - 1);

	/* max_nr_buckets must be power of two */
	if (!max_nr_buckets || (max_nr_buckets & (max_nr_buckets - 1)))
		return NULL;

	if (flags & LTTNG_UST_LFHT_AUTO_RESIZE)
		return NULL;

	min_nr_alloc_buckets = max(min_nr_alloc_buckets, MIN_TABLE_SIZE);
	init_size = max(init_size, MIN_TABLE_SIZE);
	max_nr_buckets = max(max_nr_buckets, min_nr_alloc_buckets);
	init_size = min(init_size, max_nr_buckets);

	ht = mm->alloc_lttng_ust_lfht(min_nr_alloc_buckets, max_nr_buckets);
	assert(ht);
	assert(ht->mm == mm);
	assert(ht->bucket_at == mm->bucket_at);

	ht->flags = flags;
	/* this mutex should not nest in read-side C.S. */
	pthread_mutex_init(&ht->resize_mutex, NULL);
	order = lttng_ust_lfht_get_count_order_ulong(init_size);
	ht->resize_target = 1UL << order;
	lttng_ust_lfht_create_bucket(ht, 1UL << order);
	ht->size = 1UL << order;
	return ht;
}

void lttng_ust_lfht_lookup(struct lttng_ust_lfht *ht, unsigned long hash,
		lttng_ust_lfht_match_fct match, const void *key,
		struct lttng_ust_lfht_iter *iter)
{
	struct lttng_ust_lfht_node *node, *next, *bucket;
	unsigned long reverse_hash, size;

	lttng_ust_lfht_iter_debug_set_ht(ht, iter);

	reverse_hash = bit_reverse_ulong(hash);

	size = lttng_ust_rcu_dereference(ht->size);
	bucket = lookup_bucket(ht, size, hash);
	/* We can always skip the bucket node initially */
	node = lttng_ust_rcu_dereference(bucket->next);
	node = clear_flag(node);
	for (;;) {
		if (caa_unlikely(is_end(node))) {
			node = next = NULL;
			break;
		}
		if (caa_unlikely(node->reverse_hash > reverse_hash)) {
			node = next = NULL;
			break;
		}
		next = lttng_ust_rcu_dereference(node->next);
		assert(node == clear_flag(node));
		if (caa_likely(!is_removed(next))
		    && !is_bucket(next)
		    && node->reverse_hash == reverse_hash
		    && caa_likely(match(node, key))) {
				break;
		}
		node = clear_flag(next);
	}
	assert(!node || !is_bucket(CMM_LOAD_SHARED(node->next)));
	iter->node = node;
	iter->next = next;
}

void lttng_ust_lfht_next_duplicate(struct lttng_ust_lfht *ht __attribute__((unused)),
		lttng_ust_lfht_match_fct match,
		const void *key, struct lttng_ust_lfht_iter *iter)
{
	struct lttng_ust_lfht_node *node, *next;
	unsigned long reverse_hash;

	lttng_ust_lfht_iter_debug_assert(ht == iter->lfht);
	node = iter->node;
	reverse_hash = node->reverse_hash;
	next = iter->next;
	node = clear_flag(next);

	for (;;) {
		if (caa_unlikely(is_end(node))) {
			node = next = NULL;
			break;
		}
		if (caa_unlikely(node->reverse_hash > reverse_hash)) {
			node = next = NULL;
			break;
		}
		next = lttng_ust_rcu_dereference(node->next);
		if (caa_likely(!is_removed(next))
		    && !is_bucket(next)
		    && caa_likely(match(node, key))) {
				break;
		}
		node = clear_flag(next);
	}
	assert(!node || !is_bucket(CMM_LOAD_SHARED(node->next)));
	iter->node = node;
	iter->next = next;
}

void lttng_ust_lfht_next(struct lttng_ust_lfht *ht __attribute__((unused)),
		struct lttng_ust_lfht_iter *iter)
{
	struct lttng_ust_lfht_node *node, *next;

	lttng_ust_lfht_iter_debug_assert(ht == iter->lfht);
	node = clear_flag(iter->next);
	for (;;) {
		if (caa_unlikely(is_end(node))) {
			node = next = NULL;
			break;
		}
		next = lttng_ust_rcu_dereference(node->next);
		if (caa_likely(!is_removed(next))
		    && !is_bucket(next)) {
				break;
		}
		node = clear_flag(next);
	}
	assert(!node || !is_bucket(CMM_LOAD_SHARED(node->next)));
	iter->node = node;
	iter->next = next;
}

void lttng_ust_lfht_first(struct lttng_ust_lfht *ht, struct lttng_ust_lfht_iter *iter)
{
	lttng_ust_lfht_iter_debug_set_ht(ht, iter);
	/*
	 * Get next after first bucket node. The first bucket node is the
	 * first node of the linked list.
	 */
	iter->next = bucket_at(ht, 0)->next;
	lttng_ust_lfht_next(ht, iter);
}

void lttng_ust_lfht_add(struct lttng_ust_lfht *ht, unsigned long hash,
		struct lttng_ust_lfht_node *node)
{
	unsigned long size;

	node->reverse_hash = bit_reverse_ulong(hash);
	size = lttng_ust_rcu_dereference(ht->size);
	_lttng_ust_lfht_add(ht, hash, NULL, NULL, size, node, NULL, 0);
}

struct lttng_ust_lfht_node *lttng_ust_lfht_add_unique(struct lttng_ust_lfht *ht,
				unsigned long hash,
				lttng_ust_lfht_match_fct match,
				const void *key,
				struct lttng_ust_lfht_node *node)
{
	unsigned long size;
	struct lttng_ust_lfht_iter iter;

	node->reverse_hash = bit_reverse_ulong(hash);
	size = lttng_ust_rcu_dereference(ht->size);
	_lttng_ust_lfht_add(ht, hash, match, key, size, node, &iter, 0);
	return iter.node;
}

struct lttng_ust_lfht_node *lttng_ust_lfht_add_replace(struct lttng_ust_lfht *ht,
				unsigned long hash,
				lttng_ust_lfht_match_fct match,
				const void *key,
				struct lttng_ust_lfht_node *node)
{
	unsigned long size;
	struct lttng_ust_lfht_iter iter;

	node->reverse_hash = bit_reverse_ulong(hash);
	size = lttng_ust_rcu_dereference(ht->size);
	for (;;) {
		_lttng_ust_lfht_add(ht, hash, match, key, size, node, &iter, 0);
		if (iter.node == node) {
			return NULL;
		}

		if (!_lttng_ust_lfht_replace(ht, size, iter.node, iter.next, node))
			return iter.node;
	}
}

int lttng_ust_lfht_replace(struct lttng_ust_lfht *ht,
		struct lttng_ust_lfht_iter *old_iter,
		unsigned long hash,
		lttng_ust_lfht_match_fct match,
		const void *key,
		struct lttng_ust_lfht_node *new_node)
{
	unsigned long size;

	new_node->reverse_hash = bit_reverse_ulong(hash);
	if (!old_iter->node)
		return -ENOENT;
	if (caa_unlikely(old_iter->node->reverse_hash != new_node->reverse_hash))
		return -EINVAL;
	if (caa_unlikely(!match(old_iter->node, key)))
		return -EINVAL;
	size = lttng_ust_rcu_dereference(ht->size);
	return _lttng_ust_lfht_replace(ht, size, old_iter->node, old_iter->next,
			new_node);
}

int lttng_ust_lfht_del(struct lttng_ust_lfht *ht, struct lttng_ust_lfht_node *node)
{
	unsigned long size;

	size = lttng_ust_rcu_dereference(ht->size);
	return _lttng_ust_lfht_del(ht, size, node);
}

int lttng_ust_lfht_is_node_deleted(const struct lttng_ust_lfht_node *node)
{
	return is_removed(CMM_LOAD_SHARED(node->next));
}

static
int lttng_ust_lfht_delete_bucket(struct lttng_ust_lfht *ht)
{
	struct lttng_ust_lfht_node *node;
	unsigned long order, i, size;

	/* Check that the table is empty */
	node = bucket_at(ht, 0);
	do {
		node = clear_flag(node)->next;
		if (!is_bucket(node))
			return -EPERM;
		assert(!is_removed(node));
		assert(!is_removal_owner(node));
	} while (!is_end(node));
	/*
	 * size accessed without lttng_ust_rcu_dereference because hash table is
	 * being destroyed.
	 */
	size = ht->size;
	/* Internal sanity check: all nodes left should be buckets */
	for (i = 0; i < size; i++) {
		node = bucket_at(ht, i);
		dbg_printf("delete bucket: index %lu expected hash %lu hash %lu\n",
			i, i, bit_reverse_ulong(node->reverse_hash));
		assert(is_bucket(node->next));
	}

	for (order = lttng_ust_lfht_get_count_order_ulong(size); (long)order >= 0; order--)
		lttng_ust_lfht_free_bucket_table(ht, order);

	return 0;
}

/*
 * Should only be called when no more concurrent readers nor writers can
 * possibly access the table.
 */
int lttng_ust_lfht_destroy(struct lttng_ust_lfht *ht)
{
	int ret;

	ret = lttng_ust_lfht_delete_bucket(ht);
	if (ret)
		return ret;
	ret = pthread_mutex_destroy(&ht->resize_mutex);
	if (ret)
		ret = -EBUSY;
	poison_free(ht);
	return ret;
}
