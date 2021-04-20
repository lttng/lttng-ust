/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include "lib/lttng-ust-tracepoint/tracepoint.h"

/* Test compiler support for weak symbols with hidden visibility. */
int lttng_ust_tracepoint_test_symbol1 __attribute__((weak, visibility("hidden")));
void *lttng_ust_tracepoint_test_symbol2 __attribute__((weak, visibility("hidden")));
struct {
	char a[24];
} lttng_ust_tracepoint_test_symbol3 __attribute__((weak, visibility("hidden")));

void *lttng_ust_tp_check_weak_hidden1(void)
{
	return &lttng_ust_tracepoint_test_symbol1;
}

void *lttng_ust_tp_check_weak_hidden2(void)
{
	return &lttng_ust_tracepoint_test_symbol2;
}

void *lttng_ust_tp_check_weak_hidden3(void)
{
	return &lttng_ust_tracepoint_test_symbol3;
}
