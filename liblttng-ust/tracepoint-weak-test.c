/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

/* Test compiler support for weak symbols with hidden visibility. */
int __tracepoint_test_symbol1 __attribute__((weak, visibility("hidden")));
void *__tracepoint_test_symbol2 __attribute__((weak, visibility("hidden")));
struct {
	char a[24];
} __tracepoint_test_symbol3 __attribute__((weak, visibility("hidden")));

__attribute__((visibility("hidden")))
void *lttng_ust_tp_check_weak_hidden1(void)
{
	return &__tracepoint_test_symbol1;
}

__attribute__((visibility("hidden")))
void *lttng_ust_tp_check_weak_hidden2(void)
{
	return &__tracepoint_test_symbol2;
}

__attribute__((visibility("hidden")))
void *lttng_ust_tp_check_weak_hidden3(void)
{
	return &__tracepoint_test_symbol3;
}
