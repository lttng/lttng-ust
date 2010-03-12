/* Copyright (C) 2009  Pierre-Marc Fournier
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

#ifndef KERNELCOMPAT_H
#define KERNELCOMPAT_H

#include <kcompat.h>
#include <urcu/list.h>

/* FIXME: libkcompat must not define arch-specific local ops, as ust *must*
 * fallback to the normal atomic ops. Fix things so we don't add them and
 * break things accidentally.
 */

#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})

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

#define zmalloc(s) calloc(1, s)

/* ATTRIBUTES */

/* FIXME: define this */
#define ____cacheline_aligned

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
#define PAGE_MASK (~(PAGE_SIZE-1))




/* ARRAYS */

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/* TRACE CLOCK */

/* There are two types of clocks that can be used.
   - TSC based clock
   - gettimeofday() clock

   Microbenchmarks on Linux 2.6.30 on Core2 Duo 3GHz (functions are inlined):
     Calls (100000000) to tsc(): 4004035641 cycles or 40 cycles/call
     Calls (100000000) to gettimeofday(): 9723158352 cycles or 97 cycles/call

   For merging traces with the kernel, a time source compatible with that of
   the kernel is necessary.

*/

#if 0
/* WARNING: Make sure to set frequency and scaling functions that will not
 * result in lttv timestamps (sec.nsec) with seconds greater than 2**32-1.
 */
static inline u64 trace_clock_read64(void)
{
	uint32_t low;
	uint32_t high;
	uint64_t retval;
	__asm__ volatile ("rdtsc\n" : "=a" (low), "=d" (high));

	retval = high;
	retval <<= 32;
	return retval | low;
}
#endif

#include <sys/time.h>

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

#endif /* KERNELCOMPAT_H */
