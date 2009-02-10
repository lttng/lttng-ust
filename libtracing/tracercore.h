/*
 * Copyright (C) 2005,2006 Mathieu Desnoyers (mathieu.desnoyers@polymtl.ca)
 *
 * This contains the core definitions for the Linux Trace Toolkit.
 */

#ifndef LTT_CORE_H
#define LTT_CORE_H

#include "list.h"
#include "kernelcompat.h"
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

/*
 * get dentry of ltt's root dir
 */
struct dentry *get_ltt_root(void);

/* Keep track of trap nesting inside LTT */
//ust// DECLARE_PER_CPU(unsigned int, ltt_nesting);

typedef int (*ltt_run_filter_functor)(void *trace, uint16_t eID);

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

#endif /* LTT_CORE_H */
