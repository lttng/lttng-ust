/*
 * Copyright (C) 2005,2006 Mathieu Desnoyers (mathieu.desnoyers@polymtl.ca)
 *
 * This contains the core definitions for the Linux Trace Toolkit.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#ifndef UST_TRACERCORE_H
#define UST_TRACERCORE_H

#include <ust/kernelcompat.h>
//ust// #include <linux/percpu.h>

/* ltt's root dir in debugfs */
#define LTT_ROOT        "ltt"

/*
 * All modifications of ltt_traces must be done by ltt-tracer.c, while holding
 * the semaphore. Only reading of this information can be done elsewhere, with
 * the RCU mechanism : the preemption must be disabled while reading the
 * list.
 */
struct ltt_traces {
	struct list_head setup_head;	/* Pre-allocated traces list */
	struct list_head head;		/* Allocated Traces list */
	unsigned int num_active_traces;	/* Number of active traces */
} ____cacheline_aligned;

extern struct ltt_traces ltt_traces;

/* Keep track of trap nesting inside LTT */
//ust// DECLARE_PER_CPU(unsigned int, ltt_nesting);
extern unsigned int ltt_nesting;

typedef int (*ltt_run_filter_functor)(void *trace, uint16_t eID);
//typedef int (*ltt_run_filter_functor)(void *, __u16);

extern ltt_run_filter_functor ltt_run_filter;

extern void ltt_filter_register(ltt_run_filter_functor func);
extern void ltt_filter_unregister(void);

#if defined(CONFIG_LTT) && defined(CONFIG_LTT_ALIGNMENT)

/*
 * Calculate the offset needed to align the type.
 * size_of_type must be non-zero.
 */
static inline unsigned int ltt_align(size_t align_drift, size_t size_of_type)
{
	size_t alignment = min(sizeof(void *), size_of_type);
	return (alignment - align_drift) & (alignment - 1);
}
/* Default arch alignment */
#define LTT_ALIGN

static inline int ltt_get_alignment(void)
{
	return sizeof(void *);
}

#else

static inline unsigned int ltt_align(size_t align_drift,
		 size_t size_of_type)
{
	return 0;
}

#define LTT_ALIGN __attribute__((packed))

static inline int ltt_get_alignment(void)
{
	return 0;
}
#endif /* defined(CONFIG_LTT) && defined(CONFIG_LTT_ALIGNMENT) */

#endif /* UST_TRACERCORE_H */
