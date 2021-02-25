/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2010-2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _LTTNG_UST_COMPAT_H
#define _LTTNG_UST_COMPAT_H

#include <unistd.h>
#include <limits.h>

#ifdef __FreeBSD__
#include <machine/param.h>
#endif

#ifdef _SC_PAGE_SIZE
#define LTTNG_UST_PAGE_SIZE	sysconf(_SC_PAGE_SIZE)
#elif defined(PAGE_SIZE)
#define LTTNG_UST_PAGE_SIZE	PAGE_SIZE
#else
#error "Please add page size detection for your OS."
#endif

#define LTTNG_UST_PAGE_MASK	(~(LTTNG_UST_PAGE_SIZE - 1))

#define __LTTNG_UST_ALIGN_MASK(v, mask)	(((v) + (mask)) & ~(mask))
#define LTTNG_UST_ALIGN(v, align)	__LTTNG_UST_ALIGN_MASK(v, (__typeof__(v)) (align) - 1)
#define LTTNG_UST_PAGE_ALIGN(addr)	LTTNG_UST_ALIGN(addr, LTTNG_UST_PAGE_SIZE)

#endif
