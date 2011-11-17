#ifndef _LTT_TRACER_H
#define _LTT_TRACER_H

/*
 * Copyright (C) 2005-2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This contains the definitions for the Linux Trace Toolkit tracer.
 *
 * Ported to userspace by Pierre-Marc Fournier.
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

#include <stdarg.h>
#include <stdint.h>
#include <lttng/core.h>
#include <lttng/ust-events.h>
#include "ltt-tracer-core.h"
#include "compat.h"

/* Number of bytes to log with a read/write event */
#define LTT_LOG_RW_SIZE			32L
#define LTT_MAX_SMALL_SIZE		0xFFFFU

/* Tracer properties */
#define CTF_MAGIC_NUMBER		0xC1FC1FC1
#define TSDL_MAGIC_NUMBER		0x75D11D57

/* CTF specification version followed */
#define CTF_SPEC_MAJOR			1
#define CTF_SPEC_MINOR			8

/* Tracer major/minor versions */
#define CTF_VERSION_MAJOR		0
#define CTF_VERSION_MINOR		1

/*
 * Number of milliseconds to retry before failing metadata writes on buffer full
 * condition. (10 seconds)
 */
#define LTTNG_METADATA_TIMEOUT_MSEC	10000

#define LTT_RFLAG_EXTENDED		RING_BUFFER_RFLAG_END
#define LTT_RFLAG_END			(LTT_RFLAG_EXTENDED << 1)

#endif /* _LTT_TRACER_H */
