/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2005-2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This contains the definitions for the Linux Trace Toolkit tracer.
 *
 * Ported to userspace by Pierre-Marc Fournier.
 */

#ifndef _LTTNG_TRACER_H
#define _LTTNG_TRACER_H

#include <stdarg.h>
#include <stdint.h>
#include <lttng/ust-events.h>
#include "lttng-tracer-core.h"
#include "compat.h"

/* Tracer properties */
#define CTF_MAGIC_NUMBER		0xC1FC1FC1
#define TSDL_MAGIC_NUMBER		0x75D11D57

/* CTF specification version followed */
#define CTF_SPEC_MAJOR			1
#define CTF_SPEC_MINOR			8

/*
 * Number of milliseconds to retry before failing metadata writes on buffer full
 * condition. (10 seconds)
 */
#define LTTNG_METADATA_TIMEOUT_MSEC	10000

#define LTTNG_RFLAG_EXTENDED		RING_BUFFER_RFLAG_END
#define LTTNG_RFLAG_END			(LTTNG_RFLAG_EXTENDED << 1)

#endif /* _LTTNG_TRACER_H */
