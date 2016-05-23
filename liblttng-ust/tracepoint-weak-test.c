/*
 * Copyright (C) 2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
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
