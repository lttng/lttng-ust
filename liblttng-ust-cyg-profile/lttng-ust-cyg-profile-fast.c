/*
 * Copyright (C) 2011-2013  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#define _GNU_SOURCE
#define _LGPL_SOURCE
#include <dlfcn.h>
#include <sys/types.h>
#include <stdio.h>

#define TRACEPOINT_DEFINE
#define TRACEPOINT_CREATE_PROBES
#define TP_IP_PARAM func_addr
#include "lttng-ust-cyg-profile-fast.h"

void __cyg_profile_func_enter(void *this_fn, void *call_site)
	__attribute__((no_instrument_function));

void __cyg_profile_func_exit(void *this_fn, void *call_site)
	__attribute__((no_instrument_function));

void __cyg_profile_func_enter(void *this_fn, void *call_site)
{
	tracepoint(lttng_ust_cyg_profile_fast, func_entry, this_fn);
}

void __cyg_profile_func_exit(void *this_fn, void *call_site)
{
	tracepoint(lttng_ust_cyg_profile_fast, func_exit, this_fn);
}
