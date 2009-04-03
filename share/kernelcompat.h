#ifndef KERNELCOMPAT_H
#define KERNELCOMPAT_H

#include <kcompat.h>

#include "compiler.h"

#include <string.h>
#include <sys/time.h>

/* FIXME: libkcompat must not define arch-specific local ops, as ust *must*
 * fallback to the normal atomic ops. Fix things so we don't add them and
 * break things accidentally.
 */

#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})

#define KERN_DEBUG ""
#define KERN_NOTICE ""
#define KERN_INFO ""
#define KERN_ERR ""
#define KERN_ALERT ""
#define KERN_WARNING ""

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


/* Min / Max */

#define min_t(type, x, y) ({                    \
	type __min1 = (x);                      \
	type __min2 = (y);                      \
	__min1 < __min2 ? __min1: __min2; })

#define max_t(type, x, y) ({                    \
	type __max1 = (x);                      \
	type __max2 = (y);                      \
	__max1 > __max2 ? __max1: __max2; })


/* MUTEXES */

#include <pthread.h>

#define DEFINE_MUTEX(m) pthread_mutex_t (m) = PTHREAD_MUTEX_INITIALIZER;
#define DECLARE_MUTEX(m) extern pthread_mutex_t (m);

#define mutex_lock(m) pthread_mutex_lock(m)

#define mutex_unlock(m) pthread_mutex_unlock(m)


/* MALLOCATION */

#include <stdlib.h>

#define kmalloc(s, t) malloc(s)
#define kzalloc(s, t) zmalloc(s)
#define kfree(p) free((void *)p)
#define kstrdup(s, t) strdup(s)

#define zmalloc(s) calloc(1, s)

#define GFP_KERNEL

/* PRINTK */

#include <stdio.h>
#define printk(fmt, args...) printf(fmt, ## args)


/* ATTRIBUTES */

#define ____cacheline_aligned
#define __init
#define __exit

/* MATH */

static inline unsigned int hweight32(unsigned int w)
{
	unsigned int res = w - ((w >> 1) & 0x55555555);
	res = (res & 0x33333333) + ((res >> 2) & 0x33333333);
	res = (res + (res >> 4)) & 0x0F0F0F0F;
	res = res + (res >> 8);
	return (res + (res >> 16)) & 0x000000FF;
}

static inline int fls(int x)
{
        int r;
//ust// #ifdef CONFIG_X86_CMOV
        asm("bsrl %1,%0\n\t"
            "cmovzl %2,%0"
            : "=&r" (r) : "rm" (x), "rm" (-1));
//ust// #else
//ust//         asm("bsrl %1,%0\n\t"
//ust//             "jnz 1f\n\t"
//ust//             "movl $-1,%0\n"
//ust//             "1:" : "=r" (r) : "rm" (x));
//ust// #endif
        return r + 1;
}

static __inline__ int get_count_order(unsigned int count)
{
	int order;
	
	order = fls(count) - 1;
	if (count & (count - 1))
		order++;
	return order;
}




#include <unistd.h>

#define ALIGN(x,a)		__ALIGN_MASK(x,(typeof(x))(a)-1)
#define __ALIGN_MASK(x,mask)	(((x)+(mask))&~(mask))
#define PAGE_ALIGN(addr) ALIGN(addr, PAGE_SIZE)
#define PAGE_SIZE sysconf(_SC_PAGE_SIZE)
#define PAGE_MASK (PAGE_SIZE-1)




/* ARRAYS */

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/* TRACE CLOCK */

//ust// static inline u64 trace_clock_read64(void)
//ust// {
//ust// 	uint32_t low;
//ust// 	uint32_t high;
//ust// 	uint64_t retval;
//ust// 	__asm__ volatile ("rdtsc\n" : "=a" (low), "=d" (high));
//ust// 
//ust// 	retval = high;
//ust// 	retval <<= 32;
//ust// 	return retval | low;
//ust// }

static inline u64 trace_clock_read64(void)
{
	struct timeval tv;
	u64 retval;

	gettimeofday(&tv, NULL);
	retval = tv.tv_sec;
	retval *= 1000000;
	retval += tv.tv_usec;

	return retval;
}

static inline u64 trace_clock_frequency(void)
{
	return 1000000LL;
}

static inline u32 trace_clock_freq_scale(void)
{
	return 1;
}


/* LISTS */

#define list_add_rcu list_add
#define list_for_each_entry_rcu list_for_each_entry


#define EXPORT_SYMBOL_GPL(a) /*nothing*/

#define smp_processor_id() (-1)

#endif /* KERNELCOMPAT_H */
