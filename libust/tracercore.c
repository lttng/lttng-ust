/*
 * LTT core in-kernel infrastructure.
 *
 * Copyright 2006 - Mathieu Desnoyers mathieu.desnoyers@polymtl.ca
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

#include "tracercore.h"

/* Traces structures */
struct ltt_traces ltt_traces = {
	.setup_head = LIST_HEAD_INIT(ltt_traces.setup_head),
	.head = LIST_HEAD_INIT(ltt_traces.head),
};

/* Traces list writer locking */
static DEFINE_MUTEX(ltt_traces_mutex);

void ltt_lock_traces(void)
{
	pthread_mutex_lock(&ltt_traces_mutex);
}

void ltt_unlock_traces(void)
{
	pthread_mutex_unlock(&ltt_traces_mutex);
}

//ust// DEFINE_PER_CPU(unsigned int, ltt_nesting);
//ust// EXPORT_PER_CPU_SYMBOL(ltt_nesting);
__thread int ltt_nesting;

int ltt_run_filter_default(void *trace, uint16_t eID)
{
	return 1;
}

/* This function pointer is protected by a trace activation check */
ltt_run_filter_functor ltt_run_filter = ltt_run_filter_default;

void ltt_filter_register(ltt_run_filter_functor func)
{
	ltt_run_filter = func;
}

void ltt_filter_unregister(void)
{
	ltt_run_filter = ltt_run_filter_default;
}
