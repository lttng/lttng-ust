/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2005-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This contains the core definitions for the Linux Trace Toolkit.
 */

#ifndef _LTTNG_UST_TRACER_H
#define _LTTNG_UST_TRACER_H

#include <limits.h>

#include <lttng/ust-arch.h>
#include <lttng/ust-compiler.h>
#include <lttng/ust-config.h>
#include <lttng/ust-utils.h>
#include <lttng/ust-version.h>

#ifndef LTTNG_UST_ARCH_HAS_EFFICIENT_UNALIGNED_ACCESS
/* Align data on its natural alignment */
#define RING_BUFFER_ALIGN
#endif

#ifndef CHAR_BIT
#define CHAR_BIT 8
#endif

#ifdef RING_BUFFER_ALIGN
#define lttng_alignof(type)	__alignof__(type)
#else
#define lttng_alignof(type)	1
#endif

#endif /* _LTTNG_UST_TRACER_H */
