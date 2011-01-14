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

#ifndef _UST_CLOCK_H
#define _UST_CLOCK_H

#include <time.h>
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

   Instead of gettimeofday(), we are now using clock_gettime for better
   precision and monotonicity.
*/

#if __i386__ || __x86_64__
/* Only available for x86 arch */
#define CLOCK_TRACE_FREQ  14
#define CLOCK_TRACE  15
union lttng_timespec {
	struct timespec ts;
	u64 lttng_ts;
};
#endif /* __i386__ || __x86_64__ */

extern int ust_clock_source;

/* Choosing correct trace clock */
#if __PPC__
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

#else	/* !__PPC__ */

static __inline__ u64 trace_clock_read64(void)
{
	struct timespec ts;
	u64 retval;
	union lttng_timespec *lts = (union lttng_timespec *) &ts;

	clock_gettime(ust_clock_source, &ts);
	/*
	 * Clock source can change when loading the binary (tracectl.c)
	 * so we must check if the clock source has changed before
	 * returning the correct value
	 */
	if (likely(ust_clock_source == CLOCK_TRACE)) {
		retval = lts->lttng_ts;
	} else { /* CLOCK_MONOTONIC */
		retval = ts.tv_sec;
		retval *= 1000000000;
		retval += ts.tv_nsec;
	}

	return retval;
}

#endif /* __PPC__ */

static __inline__ u64 trace_clock_frequency(void)
{
	struct timespec ts;
	union lttng_timespec *lts = (union lttng_timespec *) &ts;

	if (likely(ust_clock_source == CLOCK_TRACE)) {
		clock_gettime(CLOCK_TRACE_FREQ, &ts);
		return lts->lttng_ts;
	}
	return 1000000000LL;
}

static __inline__ u32 trace_clock_freq_scale(void)
{
	return 1;
}

#endif /* _UST_CLOCK_H */
