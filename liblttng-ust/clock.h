/*
 * Copyright (C) 2010  Pierre-Marc Fournier
 * Copyright (C) 2011  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; version 2.1 of
 * the License.
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
#include <stdint.h>
#include <stddef.h>

/* TRACE CLOCK */

/*
 * Currently using the kernel MONOTONIC clock, waiting for kernel-side
 * LTTng to implement mmap'd trace clock.
 */

/* Choosing correct trace clock */

static __inline__ uint64_t trace_clock_read64(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (ts.tv_sec * 1000000000) + ts.tv_nsec;
}

#if __i386__ || __x86_64__
static __inline__ uint64_t trace_clock_frequency(void)
{
	return 1000000000LL;
}
#endif /* #else #if __i386__ || __x86_64__ */

static __inline__ uint32_t trace_clock_freq_scale(void)
{
	return 1;
}

#endif /* _UST_CLOCK_H */
