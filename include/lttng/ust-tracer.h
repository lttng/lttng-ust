// SPDX-FileCopyrightText: 2005-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
//
// SPDX-License-Identifier: MIT

/*
 * This contains the core definitions for the Linux Trace Toolkit.
 */

#ifndef _LTTNG_UST_TRACER_H
#define _LTTNG_UST_TRACER_H

#include <lttng/ust-arch.h>
#include <lttng/ust-compiler.h>
#include <lttng/ust-utils.h>
#include <lttng/ust-version.h>

/*
 * On architectures without efficient unaligned accesses, the layout of
 * the ringbuffer's content respects the natural alignment of the
 * system. Only pack its content on architectures we know have efficient
 * unaligned memory access.
 *
 * Whether to pack the ring buffer contents or not is part of the ABI
 * between the probe providers and the tracer, and is selected by the
 * lttng/ust-arch.h header.
 */
#ifndef LTTNG_UST_ARCH_HAS_EFFICIENT_UNALIGNED_ACCESS
#define LTTNG_UST_RING_BUFFER_NATURAL_ALIGN
#endif

#ifdef LTTNG_UST_RING_BUFFER_NATURAL_ALIGN
#define lttng_ust_rb_alignof(type)	__alignof__(type)
#else
#define lttng_ust_rb_alignof(type)	1
#endif

/*
 * Concatenate lttng ust shared libraries name with their major version number.
 */
#define LTTNG_UST_LIB_SONAME "liblttng-ust.so." lttng_ust_stringify(LTTNG_UST_LIB_SONAME_MAJOR)
#define LTTNG_UST_TRACEPOINT_LIB_SONAME "liblttng-ust-tracepoint.so." lttng_ust_stringify(LTTNG_UST_LIB_SONAME_MAJOR)
#define LTTNG_UST_CTL_LIB_SONAME "liblttng-ust-ctl.so." lttng_ust_stringify(LTTNG_UST_CTL_LIB_SONAME_MAJOR)


#endif /* _LTTNG_UST_TRACER_H */
