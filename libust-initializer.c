/*
 * Copyright (C) 2009 Novell Inc.
 *
 * Author: Jan Blunck <jblunck@suse.de>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version 2.1 as
 * published by the Free  Software Foundation.
 */

#include <ust/marker.h>
#include <ust/tracepoint.h>

/* FIXME: We have to define at least one trace_mark and
 * one tracepoint here. If we don't, the __start... and
 * __stop... symbols won't be defined and the constructors
 * won't be compilable. We should find a linker trick to
 * avoid this.
 */

DECLARE_TRACE(ust_dummytp, TP_PROTO(int anint), TP_ARGS(anint));
DEFINE_TRACE(ust_dummytp);

#define CREATE_TRACE_POINTS
#include "libust-initializer.h"

void dummy_libust_initializer_func(void)
{
	trace_mark(ust, dummymark, MARK_NOARGS);
	trace_ust_dummytp(0);
	trace_ust_dummy_event(0);
}

MARKER_LIB;
TRACEPOINT_LIB;
TRACE_EVENT_LIB;
