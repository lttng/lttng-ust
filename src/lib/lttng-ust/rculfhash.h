/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright 2011 Lai Jiangshan <laijs@cn.fujitsu.com>
 *
 * Userspace RCU library - Lock-Free RCU Hash Table
 */

#ifndef _LTTNG_UST_RCULFHASH_H
#define _LTTNG_UST_RCULFHASH_H

#include <stdint.h>
#include <pthread.h>
#include <urcu/compiler.h>

#ifdef __cplusplus
extern "C" {
#endif

struct lttng_ust_lfht;

/*
 * lttng_ust_lfht_node: Contains the next pointers and reverse-hash
 * value required for lookup and traversal of the hash table.
 *
 * struct lttng_ust_lfht_node should be aligned on 8-bytes boundaries because
 * the three lower bits are used as flags. It is worth noting that the
 * information contained within these three bits could be represented on
 * two bits by re-using the same bit for REMOVAL_OWNER_FLAG and
 * BUCKET_FLAG. This can be done if we ensure that no iterator nor
 * updater check the BUCKET_FLAG after it detects that the REMOVED_FLAG
 * is set. Given the minimum size of struct lttng_ust_lfht_node is 8 bytes on
 * 32-bit architectures, we choose to go for simplicity and reserve
 * three bits.
 *
 * struct lttng_ust_lfht_node can be embedded into a structure (as a field).
 * caa_container_of() can be used to get the structure from the struct
 * lttng_ust_lfht_node after a lookup.
 *
 * The structure which embeds it typically holds the key (or key-value
 * pair) of the object. The caller code is responsible for calculation
 * of the hash value for lttng_ust_lfht APIs.
 */
struct lttng_ust_lfht_node {
	struct lttng_ust_lfht_node *next;	/* ptr | REMOVAL_OWNER_FLAG | BUCKET_FLAG | REMOVED_FLAG */
	unsigned long reverse_hash;
} __attribute__((aligned(8)));

/* lttng_ust_lfht_iter: Used to track state while traversing a hash chain. */
struct lttng_ust_lfht_iter {
	struct lttng_ust_lfht_node *node, *next;
};

static inline
struct lttng_ust_lfht_node *lttng_ust_lfht_iter_get_node(struct lttng_ust_lfht_iter *iter)
{
	return iter->node;
}

struct rcu_flavor_struct;

/*
 * Caution !
 * Ensure reader and writer threads are registered as urcu readers.
 */

typedef int (*lttng_ust_lfht_match_fct)(struct lttng_ust_lfht_node *node, const void *key);

/*
 * lttng_ust_lfht_node_init - initialize a hash table node
 * @node: the node to initialize.
 *
 * This function is kept to be eventually used for debugging purposes
 * (detection of memory corruption).
 */
static inline
void lttng_ust_lfht_node_init(struct lttng_ust_lfht_node *node __attribute__((unused)))
{
}

/*
 * Hash table creation flags.
 */
enum {
	LTTNG_UST_LFHT_AUTO_RESIZE = (1U << 0),
	LTTNG_UST_LFHT_ACCOUNTING = (1U << 1),
};

struct lttng_ust_lfht_mm_type {
	struct lttng_ust_lfht *(*alloc_lttng_ust_lfht)(unsigned long min_nr_alloc_buckets,
			unsigned long max_nr_buckets);
	void (*alloc_bucket_table)(struct lttng_ust_lfht *ht, unsigned long order);
	void (*free_bucket_table)(struct lttng_ust_lfht *ht, unsigned long order);
	struct lttng_ust_lfht_node *(*bucket_at)(struct lttng_ust_lfht *ht,
			unsigned long index);
};

extern const struct lttng_ust_lfht_mm_type lttng_ust_lfht_mm_order
	__attribute__((visibility("hidden")));

extern const struct lttng_ust_lfht_mm_type lttng_ust_lfht_mm_chunk
	__attribute__((visibility("hidden")));

extern const struct lttng_ust_lfht_mm_type lttng_ust_lfht_mm_mmap
	__attribute__((visibility("hidden")));

/*
 * lttng_ust_lfht_new - allocate a hash table.
 * @init_size: number of buckets to allocate initially. Must be power of two.
 * @min_nr_alloc_buckets: the minimum number of allocated buckets.
 *                        (must be power of two)
 * @max_nr_buckets: the maximum number of hash table buckets allowed.
 *                  (must be power of two, 0 is accepted, means
 *                  "infinite")
 * @flags: hash table creation flags (can be combined with bitwise or: '|').
 *           0: no flags.
 *           LTTNG_UST_LFHT_AUTO_RESIZE: automatically resize hash table.
 *           LTTNG_UST_LFHT_ACCOUNTING: count the number of node addition
 *                                and removal in the table
 *
 * Return NULL on error.
 * Note: the RCU flavor must be already included before the hash table header.
 */
extern struct lttng_ust_lfht *lttng_ust_lfht_new(unsigned long init_size,
			unsigned long min_nr_alloc_buckets,
			unsigned long max_nr_buckets,
			int flags,
			const struct lttng_ust_lfht_mm_type *mm)
	__attribute__((visibility("hidden")));

/*
 * lttng_ust_lfht_destroy - destroy a hash table.
 * @ht: the hash table to destroy.
 *
 * Return 0 on success, negative error value on error.

 * Prior to liburcu 0.10:
 * - Threads calling this API need to be registered RCU read-side
 *   threads.
 * - lttng_ust_lfht_destroy should *not* be called from a RCU read-side
 *   critical section. It should *not* be called from a call_rcu thread
 *   context neither.
 *
 * Starting from liburcu 0.10, rculfhash implements its own worker
 * thread to handle resize operations, which removes RCU requirements on
 * lttng_ust_lfht_destroy.
 */
extern int lttng_ust_lfht_destroy(struct lttng_ust_lfht *ht)
	__attribute__((visibility("hidden")));

/*
 * lttng_ust_lfht_count_nodes - count the number of nodes in the hash table.
 * @ht: the hash table.
 * @split_count_before: sample the node count split-counter before traversal.
 * @count: traverse the hash table, count the number of nodes observed.
 * @split_count_after: sample the node count split-counter after traversal.
 *
 * Call with rcu_read_lock held.
 * Threads calling this API need to be registered RCU read-side threads.
 */
extern void lttng_ust_lfht_count_nodes(struct lttng_ust_lfht *ht,
		long *split_count_before,
		unsigned long *count,
		long *split_count_after)
	__attribute__((visibility("hidden")));

/*
 * lttng_ust_lfht_lookup - lookup a node by key.
 * @ht: the hash table.
 * @hash: the key hash.
 * @match: the key match function.
 * @key: the current node key.
 * @iter: node, if found (output). *iter->node set to NULL if not found.
 *
 * Call with rcu_read_lock held.
 * Threads calling this API need to be registered RCU read-side threads.
 * This function acts as a rcu_dereference() to read the node pointer.
 */
extern void lttng_ust_lfht_lookup(struct lttng_ust_lfht *ht, unsigned long hash,
		lttng_ust_lfht_match_fct match, const void *key,
		struct lttng_ust_lfht_iter *iter)
	__attribute__((visibility("hidden")));

/*
 * lttng_ust_lfht_next_duplicate - get the next item with same key, after iterator.
 * @ht: the hash table.
 * @match: the key match function.
 * @key: the current node key.
 * @iter: input: current iterator.
 *        output: node, if found. *iter->node set to NULL if not found.
 *
 * Uses an iterator initialized by a lookup or traversal. Important: the
 * iterator _needs_ to be initialized before calling
 * lttng_ust_lfht_next_duplicate.
 * Sets *iter-node to the following node with same key.
 * Sets *iter->node to NULL if no following node exists with same key.
 * RCU read-side lock must be held across lttng_ust_lfht_lookup and
 * lttng_ust_lfht_next calls, and also between lttng_ust_lfht_next calls using the
 * node returned by a previous lttng_ust_lfht_next.
 * Call with rcu_read_lock held.
 * Threads calling this API need to be registered RCU read-side threads.
 * This function acts as a rcu_dereference() to read the node pointer.
 */
extern void lttng_ust_lfht_next_duplicate(struct lttng_ust_lfht *ht,
		lttng_ust_lfht_match_fct match, const void *key,
		struct lttng_ust_lfht_iter *iter)
	__attribute__((visibility("hidden")));

/*
 * lttng_ust_lfht_first - get the first node in the table.
 * @ht: the hash table.
 * @iter: First node, if exists (output). *iter->node set to NULL if not found.
 *
 * Output in "*iter". *iter->node set to NULL if table is empty.
 * Call with rcu_read_lock held.
 * Threads calling this API need to be registered RCU read-side threads.
 * This function acts as a rcu_dereference() to read the node pointer.
 */
extern void lttng_ust_lfht_first(struct lttng_ust_lfht *ht, struct lttng_ust_lfht_iter *iter)
	__attribute__((visibility("hidden")));

/*
 * lttng_ust_lfht_next - get the next node in the table.
 * @ht: the hash table.
 * @iter: input: current iterator.
 *        output: next node, if exists. *iter->node set to NULL if not found.
 *
 * Input/Output in "*iter". *iter->node set to NULL if *iter was
 * pointing to the last table node.
 * Call with rcu_read_lock held.
 * Threads calling this API need to be registered RCU read-side threads.
 * This function acts as a rcu_dereference() to read the node pointer.
 */
extern void lttng_ust_lfht_next(struct lttng_ust_lfht *ht, struct lttng_ust_lfht_iter *iter)
	__attribute__((visibility("hidden")));

/*
 * lttng_ust_lfht_add - add a node to the hash table.
 * @ht: the hash table.
 * @hash: the key hash.
 * @node: the node to add.
 *
 * This function supports adding redundant keys into the table.
 * Call with rcu_read_lock held.
 * Threads calling this API need to be registered RCU read-side threads.
 * This function issues a full memory barrier before and after its
 * atomic commit.
 */
extern void lttng_ust_lfht_add(struct lttng_ust_lfht *ht, unsigned long hash,
		struct lttng_ust_lfht_node *node)
	__attribute__((visibility("hidden")));

/*
 * lttng_ust_lfht_add_unique - add a node to hash table, if key is not present.
 * @ht: the hash table.
 * @hash: the node's hash.
 * @match: the key match function.
 * @key: the node's key.
 * @node: the node to try adding.
 *
 * Return the node added upon success.
 * Return the unique node already present upon failure. If
 * lttng_ust_lfht_add_unique fails, the node passed as parameter should be
 * freed by the caller. In this case, the caller does NOT need to wait
 * for a grace period before freeing or re-using the node.
 * Call with rcu_read_lock held.
 * Threads calling this API need to be registered RCU read-side threads.
 *
 * The semantic of this function is that if only this function is used
 * to add keys into the table, no duplicated keys should ever be
 * observable in the table. The same guarantee apply for combination of
 * add_unique and add_replace (see below).
 *
 * Upon success, this function issues a full memory barrier before and
 * after its atomic commit. Upon failure, this function acts like a
 * simple lookup operation: it acts as a rcu_dereference() to read the
 * node pointer. The failure case does not guarantee any other memory
 * barrier.
 */
extern struct lttng_ust_lfht_node *lttng_ust_lfht_add_unique(struct lttng_ust_lfht *ht,
		unsigned long hash,
		lttng_ust_lfht_match_fct match,
		const void *key,
		struct lttng_ust_lfht_node *node)
	__attribute__((visibility("hidden")));

/*
 * lttng_ust_lfht_add_replace - replace or add a node within hash table.
 * @ht: the hash table.
 * @hash: the node's hash.
 * @match: the key match function.
 * @key: the node's key.
 * @node: the node to add.
 *
 * Return the node replaced upon success. If no node matching the key
 * was present, return NULL, which also means the operation succeeded.
 * This replacement operation should never fail.
 * Call with rcu_read_lock held.
 * Threads calling this API need to be registered RCU read-side threads.
 * After successful replacement, a grace period must be waited for before
 * freeing or re-using the memory reserved for the returned node.
 *
 * The semantic of replacement vs lookups and traversals is the
 * following: if lookups and traversals are performed between a key
 * unique insertion and its removal, we guarantee that the lookups and
 * traversals will always find exactly one instance of the key if it is
 * replaced concurrently with the lookups.
 *
 * Providing this semantic allows us to ensure that replacement-only
 * schemes will never generate duplicated keys. It also allows us to
 * guarantee that a combination of add_replace and add_unique updates
 * will never generate duplicated keys.
 *
 * This function issues a full memory barrier before and after its
 * atomic commit.
 */
extern struct lttng_ust_lfht_node *lttng_ust_lfht_add_replace(struct lttng_ust_lfht *ht,
		unsigned long hash,
		lttng_ust_lfht_match_fct match,
		const void *key,
		struct lttng_ust_lfht_node *node)
	__attribute__((visibility("hidden")));

/*
 * lttng_ust_lfht_replace - replace a node pointed to by iter within hash table.
 * @ht: the hash table.
 * @old_iter: the iterator position of the node to replace.
 * @hash: the node's hash.
 * @match: the key match function.
 * @key: the node's key.
 * @new_node: the new node to use as replacement.
 *
 * Return 0 if replacement is successful, negative value otherwise.
 * Replacing a NULL old node or an already removed node will fail with
 * -ENOENT.
 * If the hash or value of the node to replace and the new node differ,
 * this function returns -EINVAL without proceeding to the replacement.
 * Old node can be looked up with lttng_ust_lfht_lookup and lttng_ust_lfht_next.
 * RCU read-side lock must be held between lookup and replacement.
 * Call with rcu_read_lock held.
 * Threads calling this API need to be registered RCU read-side threads.
 * After successful replacement, a grace period must be waited for before
 * freeing or re-using the memory reserved for the old node (which can
 * be accessed with lttng_ust_lfht_iter_get_node).
 *
 * The semantic of replacement vs lookups is the same as
 * lttng_ust_lfht_add_replace().
 *
 * Upon success, this function issues a full memory barrier before and
 * after its atomic commit. Upon failure, this function does not issue
 * any memory barrier.
 */
extern int lttng_ust_lfht_replace(struct lttng_ust_lfht *ht,
		struct lttng_ust_lfht_iter *old_iter,
		unsigned long hash,
		lttng_ust_lfht_match_fct match,
		const void *key,
		struct lttng_ust_lfht_node *new_node)
	__attribute__((visibility("hidden")));

/*
 * lttng_ust_lfht_del - remove node pointed to by iterator from hash table.
 * @ht: the hash table.
 * @node: the node to delete.
 *
 * Return 0 if the node is successfully removed, negative value
 * otherwise.
 * Deleting a NULL node or an already removed node will fail with a
 * negative value.
 * Node can be looked up with lttng_ust_lfht_lookup and lttng_ust_lfht_next,
 * followed by use of lttng_ust_lfht_iter_get_node.
 * RCU read-side lock must be held between lookup and removal.
 * Call with rcu_read_lock held.
 * Threads calling this API need to be registered RCU read-side threads.
 * After successful removal, a grace period must be waited for before
 * freeing or re-using the memory reserved for old node (which can be
 * accessed with lttng_ust_lfht_iter_get_node).
 * Upon success, this function issues a full memory barrier before and
 * after its atomic commit. Upon failure, this function does not issue
 * any memory barrier.
 */
extern int lttng_ust_lfht_del(struct lttng_ust_lfht *ht, struct lttng_ust_lfht_node *node)
	__attribute__((visibility("hidden")));

/*
 * lttng_ust_lfht_is_node_deleted - query whether a node is removed from hash table.
 *
 * Return non-zero if the node is deleted from the hash table, 0
 * otherwise.
 * Node can be looked up with lttng_ust_lfht_lookup and lttng_ust_lfht_next,
 * followed by use of lttng_ust_lfht_iter_get_node.
 * RCU read-side lock must be held between lookup and call to this
 * function.
 * Call with rcu_read_lock held.
 * Threads calling this API need to be registered RCU read-side threads.
 * This function does not issue any memory barrier.
 */
extern int lttng_ust_lfht_is_node_deleted(const struct lttng_ust_lfht_node *node)
	__attribute__((visibility("hidden")));

/*
 * lttng_ust_lfht_resize - Force a hash table resize
 * @ht: the hash table.
 * @new_size: update to this hash table size.
 *
 * Threads calling this API need to be registered RCU read-side threads.
 * This function does not (necessarily) issue memory barriers.
 * lttng_ust_lfht_resize should *not* be called from a RCU read-side critical
 * section.
 */
extern void lttng_ust_lfht_resize(struct lttng_ust_lfht *ht, unsigned long new_size)
	__attribute__((visibility("hidden")));

/*
 * Note: it is safe to perform element removal (del), replacement, or
 * any hash table update operation during any of the following hash
 * table traversals.
 * These functions act as rcu_dereference() to read the node pointers.
 */
#define lttng_ust_lfht_for_each(ht, iter, node)				\
	for (lttng_ust_lfht_first(ht, iter),					\
			node = lttng_ust_lfht_iter_get_node(iter);		\
		node != NULL;						\
		lttng_ust_lfht_next(ht, iter),				\
			node = lttng_ust_lfht_iter_get_node(iter))

#define lttng_ust_lfht_for_each_duplicate(ht, hash, match, key, iter, node)	\
	for (lttng_ust_lfht_lookup(ht, hash, match, key, iter),		\
			node = lttng_ust_lfht_iter_get_node(iter);		\
		node != NULL;						\
		lttng_ust_lfht_next_duplicate(ht, match, key, iter),		\
			node = lttng_ust_lfht_iter_get_node(iter))

#define lttng_ust_lfht_for_each_entry(ht, iter, pos, member)			\
	for (lttng_ust_lfht_first(ht, iter),					\
			pos = caa_container_of(lttng_ust_lfht_iter_get_node(iter), \
					__typeof__(*(pos)), member);	\
		lttng_ust_lfht_iter_get_node(iter) != NULL;			\
		lttng_ust_lfht_next(ht, iter),				\
			pos = caa_container_of(lttng_ust_lfht_iter_get_node(iter), \
					__typeof__(*(pos)), member))

#define lttng_ust_lfht_for_each_entry_duplicate(ht, hash, match, key,		\
				iter, pos, member)			\
	for (lttng_ust_lfht_lookup(ht, hash, match, key, iter),		\
			pos = caa_container_of(lttng_ust_lfht_iter_get_node(iter), \
					__typeof__(*(pos)), member);	\
		lttng_ust_lfht_iter_get_node(iter) != NULL;			\
		lttng_ust_lfht_next_duplicate(ht, match, key, iter),		\
			pos = caa_container_of(lttng_ust_lfht_iter_get_node(iter), \
					__typeof__(*(pos)), member))

#ifdef __cplusplus
}
#endif

#endif /* _LTTNG_UST_RCULFHASH_H */
