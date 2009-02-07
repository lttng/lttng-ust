#ifndef KERNELCOMPAT_H
#define KERNELCOMPAT_H

#include "compiler.h"

#include <string.h>

#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})

#define KERN_DEBUG
#define KERN_NOTICE

/* ERROR OPS */

#define MAX_ERRNO	4095

#define IS_ERR_VALUE(x) unlikely((x) >= (unsigned long)-MAX_ERRNO)

static inline void *ERR_PTR(long error)
{
	return (void *) error;
}

static inline long PTR_ERR(const void *ptr)
{
	return (long) ptr;
}

static inline long IS_ERR(const void *ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}


/* FIXED SIZE INTEGERS */

#include <stdint.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;


#include <pthread.h>

#define DEFINE_MUTEX(m) pthread_mutex_t (m) = PTHREAD_MUTEX_INITIALIZER;

#define mutex_lock(m) pthread_mutex_lock(m)

#define mutex_unlock(m) pthread_mutex_unlock(m)


#include <stdlib.h>

#define kmalloc(s, t) malloc(s)
#define kzalloc(s, t) malloc(s)
#define kfree(p) free((void *)p)
#define kstrdup(s, t) strdup(s)


#include <stdio.h>
#define printk(fmt, args...) printf(fmt, ## args)


/* MEMORY BARRIERS */

#define smp_rmb() do {} while(0)
#define smp_wmb() do {} while(0)
#define smp_mb() do {} while(0)
#define smp_mb__after_atomic_inc() do {} while(0)

#define read_barrier_depends() do {} while(0)
#define smp_read_barrier_depends() do {} while(0)

/* RCU */

#define rcu_assign_pointer(a, b) do {} while(0)

/* ATOMICITY */
#include <signal.h>

typedef struct { sig_atomic_t counter; } atomic_t;

static inline int atomic_dec_and_test(atomic_t *p)
{
	(p->counter)--;
	return !p->counter;
}

static inline void atomic_set(atomic_t *p, int v)
{
	p->counter=v;
}

static inline void atomic_inc(atomic_t *p)
{
	p->counter++;
}

static int atomic_read(atomic_t *p)
{
	return p->counter;
}

/* CACHE */
#define ____cacheline_aligned

#endif /* KERNELCOMPAT_H */
