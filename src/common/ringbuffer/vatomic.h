/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2010-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _LTTNG_RING_BUFFER_VATOMIC_H
#define _LTTNG_RING_BUFFER_VATOMIC_H

#include <assert.h>
#include <urcu/uatomic.h>

/*
 * Same data type (long) accessed differently depending on configuration.
 * v field is for non-atomic access (protected by mutual exclusion).
 * In the fast-path, the ring_buffer_config structure is constant, so the
 * compiler can statically select the appropriate branch.
 * local_t is used for per-cpu and per-thread buffers.
 * atomic_long_t is used for per-channel shared buffers.
 */
union v_atomic {
	long a;	/* accessed through uatomic */
	long v;
};

static inline
long v_read(const struct lttng_ust_ring_buffer_config *config, union v_atomic *v_a)
{
	assert(config->sync != RING_BUFFER_SYNC_PER_CPU);
	return uatomic_read(&v_a->a);
}

static inline
void v_set(const struct lttng_ust_ring_buffer_config *config, union v_atomic *v_a,
	   long v)
{
	assert(config->sync != RING_BUFFER_SYNC_PER_CPU);
	uatomic_set(&v_a->a, v);
}

static inline
void v_add(const struct lttng_ust_ring_buffer_config *config, long v, union v_atomic *v_a)
{
	assert(config->sync != RING_BUFFER_SYNC_PER_CPU);
	uatomic_add(&v_a->a, v);
}

static inline
void v_inc(const struct lttng_ust_ring_buffer_config *config, union v_atomic *v_a)
{
	assert(config->sync != RING_BUFFER_SYNC_PER_CPU);
	uatomic_inc(&v_a->a);
}

/*
 * Non-atomic decrement. Only used by reader, apply to reader-owned subbuffer.
 */
static inline
void _v_dec(const struct lttng_ust_ring_buffer_config *config __attribute__((unused)), union v_atomic *v_a)
{
	--v_a->v;
}

static inline
long v_cmpxchg(const struct lttng_ust_ring_buffer_config *config, union v_atomic *v_a,
	       long old, long _new)
{
	assert(config->sync != RING_BUFFER_SYNC_PER_CPU);
	return uatomic_cmpxchg(&v_a->a, old, _new);
}

#endif /* _LTTNG_RING_BUFFER_VATOMIC_H */
