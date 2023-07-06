// SPDX-FileCopyrightText: 2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
//
// SPDX-License-Identifier: LGPL-2.1-only

#ifndef LTTNG_UST_CLOCK_H
#define LTTNG_UST_CLOCK_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Set each callback for the trace clock override, and then enable the
 * override. Those functions return negative error values on error, 0 on
 * success.
 */

typedef uint64_t (*lttng_ust_clock_read64_function)(void);
typedef uint64_t (*lttng_ust_clock_freq_function)(void);
typedef int (*lttng_ust_clock_uuid_function)(char *uuid);
typedef const char *(*lttng_ust_clock_name_function)(void);
typedef const char *(*lttng_ust_clock_description_function)(void);

/*
 * Set/Get clock override read callback. This callback should return the
 * current clock time (a 64-bit monotonic counter).
 */
int lttng_ust_trace_clock_set_read64_cb(lttng_ust_clock_read64_function read64_cb);
int lttng_ust_trace_clock_get_read64_cb(lttng_ust_clock_read64_function *read64_cb);

/*
 * Set/Get clock override frequency callback. This callback should return
 * the frequency of the clock in cycles per second.
 */
int lttng_ust_trace_clock_set_freq_cb(lttng_ust_clock_freq_function freq_cb);
int lttng_ust_trace_clock_get_freq_cb(lttng_ust_clock_freq_function *freq_cb);

/*
 * Set/Get clock override unique identifier.
 * LTTNG_UST_UUID_STR_LEN is the maximum length of uuid string. Includes
 * final \0.
 */
#define LTTNG_UST_UUID_STR_LEN         37

int lttng_ust_trace_clock_set_uuid_cb(lttng_ust_clock_uuid_function uuid_cb);
int lttng_ust_trace_clock_get_uuid_cb(lttng_ust_clock_uuid_function *uuid_cb);

/*
 * Set/Get clock override name.
 */
int lttng_ust_trace_clock_set_name_cb(lttng_ust_clock_name_function name_cb);
int lttng_ust_trace_clock_get_name_cb(lttng_ust_clock_name_function *name_cb);

/*
 * Set/Get clock override description.
 */
int lttng_ust_trace_clock_set_description_cb(lttng_ust_clock_description_function description_cb);
int lttng_ust_trace_clock_get_description_cb(lttng_ust_clock_description_function *description_cb);

/*
 * Use the clock override rather than the default clock.
 */
int lttng_ust_enable_trace_clock_override(void);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_UST_CLOCK_H */
