/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2014  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef LTTNG_UST_CLOCK_H
#define LTTNG_UST_CLOCK_H

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
