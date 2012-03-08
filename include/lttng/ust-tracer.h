#ifndef _LTTNG_TRACER_H
#define _LTTNG_TRACER_H

/*
 * Copyright (C) 2005-2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This contains the core definitions for the Linux Trace Toolkit.
 *
 * Copyright 2011-2012 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 */

#include <lttng/ust-config.h>
#include <lttng/ust-version.h>

#ifndef LTTNG_UST_HAVE_EFFICIENT_UNALIGNED_ACCESS
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

#define lttng_is_signed_type(type)           (((type)(-1)) < 0)

#endif /* _LTTNG_TRACER_CORE_H */
