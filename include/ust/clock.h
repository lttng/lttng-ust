/* Copyright (C) 2010  Pierre-Marc Fournier
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

#ifndef UST_CLOCK_H
#define UST_CLOCK_H

#include <sys/time.h>
#include <ust/kcompat/kcompat.h>

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

#define TRACE_CLOCK_GENERIC
#ifdef TRACE_CLOCK_GENERIC

static __inline__ u64 trace_clock_read64(void)
{
	struct timeval tv;
	u64 retval;

	gettimeofday(&tv, NULL);
	retval = tv.tv_sec;
	retval *= 1000000;
	retval += tv.tv_usec;

	return retval;
}

#else

#if __i386 || __x86_64

/* WARNING: Make sure to set frequency and scaling functions that will not
 * result in lttv timestamps (sec.nsec) with seconds greater than 2**32-1.
 */
static __inline__ u64 trace_clock_read64(void)
{
	uint32_t low;
	uint32_t high;
	uint64_t retval;
	__asm__ volatile ("rdtsc\n" : "=a" (low), "=d" (high));

	retval = high;
	retval <<= 32;
	return retval | low;
}

#endif /* __i386 || __x86_64 */

#ifdef __PPC__

static __inline__ u64 trace_clock_read64(void)
{
	unsigned long tb_l;
	unsigned long tb_h;
	unsigned long tb_h2;
	u64 tb;

	__asm__ (
		"1:\n\t"
		"mftbu %[rhigh]\n\t"
		"mftb %[rlow]\n\t"
		"mftbu %[rhigh2]\n\t"
		"cmpw %[rhigh],%[rhigh2]\n\t"
		"bne 1b\n\t"
	: [rhigh] "=r" (tb_h), [rhigh2] "=r" (tb_h2), [rlow] "=r" (tb_l));
	
	tb = tb_h;
	tb <<= 32;
	tb |= tb_l;

	return tb;
}

#endif /* __PPC__ */

#endif /* ! UST_TRACE_CLOCK_GENERIC */

static __inline__ u64 trace_clock_frequency(void)
{
	return 1000000LL;
}

static __inline__ u32 trace_clock_freq_scale(void)
{
	return 1;
}

#endif /* UST_CLOCK_H */
