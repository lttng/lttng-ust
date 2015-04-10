#ifndef LTTNG_UST_CLOCK_H
#define LTTNG_UST_CLOCK_H

/*
 * Copyright (C) 2014  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <stdint.h>
#include <stddef.h>

/*
 * Set each callback for the trace clock override, and then enable the
 * override. Those functions return negative error values on error, 0 on
 * success.
 */

/*
 * Set clock override read callback. This callback should return the
 * current clock time (a 64-bit monotonic counter).
 */
int lttng_ust_trace_clock_set_read64_cb(uint64_t (*read64)(void));

/*
 * Set clock override frequency callback. This callback should return
 * the frequency of the clock in cycles per second.
 */
int lttng_ust_trace_clock_set_freq_cb(uint64_t (*freq)(void));

/*
 * Set clock override unique identifier.
 * LTTNG_UST_UUID_STR_LEN is the maximum length of uuid string. Includes
 * final \0.
 */
#define LTTNG_UST_UUID_STR_LEN         37

int lttng_ust_trace_clock_set_uuid_cb(int (*uuid)(char *uuid));

/*
 * Set clock override name.
 */
int lttng_ust_trace_clock_set_name_cb(const char *(*name)(void));

/*
 * Set clock override description.
 */
int lttng_ust_trace_clock_set_description_cb(const char *(*description)(void));

/*
 * Use the clock override rather than the default clock.
 */
int lttng_ust_enable_trace_clock_override(void);

#endif /* LTTNG_UST_CLOCK_H */
