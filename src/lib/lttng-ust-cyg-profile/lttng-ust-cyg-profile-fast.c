/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright (C) 2011-2013 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#define _LGPL_SOURCE
#include <dlfcn.h>
#include <sys/types.h>
#include <stdio.h>

#define LTTNG_UST_TRACEPOINT_DEFINE
#define TRACEPOINT_CREATE_PROBES
#define TP_IP_PARAM func_addr
#include "lttng-ust-cyg-profile-fast.h"

void __cyg_profile_func_enter(void *this_fn, void *call_site)
	__attribute__((no_instrument_function));

void __cyg_profile_func_exit(void *this_fn, void *call_site)
	__attribute__((no_instrument_function));

void __cyg_profile_func_enter(void *this_fn, void *call_site __attribute__((unused)))
{
	lttng_ust_tracepoint(lttng_ust_cyg_profile_fast, func_entry, this_fn);
}

void __cyg_profile_func_exit(void *this_fn, void *call_site __attribute__((unused)))
{
	lttng_ust_tracepoint(lttng_ust_cyg_profile_fast, func_exit, this_fn);
}
