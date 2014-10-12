/*
 * lttng-clock-override-example.c
 *
 * Copyright (c) 2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <lttng/ust-clock.h>

/*
 * For sake of example, transform time into a coarse clock (freq: 1KHz).
 * Note that division can be slow on some architectures. Should be
 * avoided. Use shift and multiplication instead. e.g.:
 *
 * Operation: / 1000000ULL
 * 1/1000000ULL = .000001
 * 2^19 < 1000000 < 2^20
 * Add a 10 bits shift to increase accuracy:
 * 2^(19+10) = 536870912
 * x * 1 / 2^(19+10) ~= .000001
 * 537 * 1 / 2^29 = .00000100024044513702
 * 537 (multiplication factor) is between 2^9 and 2^10.
 *
 * In order not to overflow, first right shift by 10, multiply, and right
 * shift by 19.
 */
#define DIV_CLOCK_SHIFT1	10
#define DIV_CLOCK_MUL		537
#define DIV_CLOCK_SHIFT2	19

static
uint64_t plugin_read64(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	/*
	 * This is a rather dumb example, but it illustrates the plugin
	 * mechanism: we take the monotonic clock, and transform it into
	 * a very coarse clock, which increment only at 1KHz frequency.
	 */
	return ((uint64_t) ts.tv_sec * 1000ULL)
		+ ((DIV_CLOCK_MUL * ((uint64_t) ts.tv_nsec >> DIV_CLOCK_SHIFT1))
			>> DIV_CLOCK_SHIFT2);
}

static
uint64_t plugin_freq(void)
{
	return 1000;	/* 1KHz clock (very coarse!) */
}

static
int plugin_uuid(char *uuid)
{
	const char myuuid[] = "123456789012345678901234567890123456";

	/*
	 * Should read some unique identifier for this clock shared
	 * across all components of the system using this clock for
	 * tracing.
	 */
	memcpy(uuid, myuuid, LTTNG_UST_UUID_STR_LEN);
	return 0;
}

static
const char *plugin_name(void)
{
	return "my_example_clock";
}

static
const char *plugin_description(void)
{
	return "Coarse monotonic clock at 1KHz";
}

void lttng_ust_clock_plugin_init(void)
{
	int ret;

	ret = lttng_ust_trace_clock_set_read64_cb(plugin_read64);
	if (ret) {
		fprintf(stderr, "Error setting clock override read64 callback: %s\n",
			strerror(-ret));
		goto error;
	}
	ret = lttng_ust_trace_clock_set_freq_cb(plugin_freq);
	if (ret) {
		fprintf(stderr, "Error setting clock override freq callback: %s\n",
			strerror(-ret));
		goto error;
	}
	ret = lttng_ust_trace_clock_set_uuid_cb(plugin_uuid);
	if (ret) {
		fprintf(stderr, "Error setting clock override uuid callback: %s\n",
			strerror(-ret));
		goto error;
	}

	ret = lttng_ust_trace_clock_set_name_cb(plugin_name);
	if (ret) {
		fprintf(stderr, "Error setting clock override name callback: %s\n",
			strerror(-ret));
		goto error;
	}

	ret = lttng_ust_trace_clock_set_description_cb(plugin_description);
	if (ret) {
		fprintf(stderr, "Error setting clock override description callback: %s\n",
			strerror(-ret));
		goto error;
	}

	ret = lttng_ust_enable_trace_clock_override();
	if (ret) {
		fprintf(stderr, "Error enabling clock override: %s\n",
			strerror(-ret));
		goto error;
	}

	return;

error:
	exit(EXIT_FAILURE);
}
