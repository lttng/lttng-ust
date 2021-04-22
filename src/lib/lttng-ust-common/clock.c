/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#define _LGPL_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include <lttng/ust-clock.h>
#include <lttng/ust-events.h>
#include <urcu/system.h>
#include <urcu/arch.h>

#include "common/logging.h"
#include "common/getenv.h"

#include "lib/lttng-ust-common/clock.h"

struct lttng_ust_trace_clock *lttng_ust_trace_clock;

static
struct lttng_ust_trace_clock user_tc;

static
void *clock_handle;

static
uint64_t trace_clock_freq_monotonic(void)
{
	return 1000000000ULL;
}

static
int trace_clock_uuid_monotonic(char *uuid)
{
	int ret = 0;
	size_t len;
	FILE *fp;

	/*
	 * boot_id needs to be read once before being used concurrently
	 * to deal with a Linux kernel race. A fix is proposed for
	 * upstream, but the work-around is needed for older kernels.
	 */
	fp = fopen("/proc/sys/kernel/random/boot_id", "r");
	if (!fp) {
		return -ENOENT;
	}
	len = fread(uuid, 1, LTTNG_UST_UUID_STR_LEN - 1, fp);
	if (len < LTTNG_UST_UUID_STR_LEN - 1) {
		ret = -EINVAL;
		goto end;
	}
	uuid[LTTNG_UST_UUID_STR_LEN - 1] = '\0';
end:
	fclose(fp);
	return ret;
}

static
const char *trace_clock_name_monotonic(void)
{
	return "monotonic";
}

static
const char *trace_clock_description_monotonic(void)
{
	return "Monotonic Clock";
}

int lttng_ust_trace_clock_set_read64_cb(lttng_ust_clock_read64_function read64_cb)
{
	if (CMM_LOAD_SHARED(lttng_ust_trace_clock))
		return -EBUSY;
	user_tc.read64 = read64_cb;
	return 0;
}

int lttng_ust_trace_clock_get_read64_cb(lttng_ust_clock_read64_function *read64_cb)
{
	struct lttng_ust_trace_clock *ltc = CMM_LOAD_SHARED(lttng_ust_trace_clock);

	if (caa_likely(!ltc)) {
		*read64_cb = &trace_clock_read64_monotonic;
	} else {
		cmm_read_barrier_depends();     /* load ltc before content */
		*read64_cb = ltc->read64;
	}
	return 0;
}

int lttng_ust_trace_clock_set_freq_cb(lttng_ust_clock_freq_function freq_cb)
{
	if (CMM_LOAD_SHARED(lttng_ust_trace_clock))
		return -EBUSY;
	user_tc.freq = freq_cb;
	return 0;
}

int lttng_ust_trace_clock_get_freq_cb(lttng_ust_clock_freq_function *freq_cb)
{
	struct lttng_ust_trace_clock *ltc = CMM_LOAD_SHARED(lttng_ust_trace_clock);

	if (caa_likely(!ltc)) {
		*freq_cb = &trace_clock_freq_monotonic;
	} else {
		cmm_read_barrier_depends();     /* load ltc before content */
		*freq_cb = ltc->freq;
	}
	return 0;
}

int lttng_ust_trace_clock_set_uuid_cb(lttng_ust_clock_uuid_function uuid_cb)
{
	if (CMM_LOAD_SHARED(lttng_ust_trace_clock))
		return -EBUSY;
	user_tc.uuid = uuid_cb;
	return 0;
}

int lttng_ust_trace_clock_get_uuid_cb(lttng_ust_clock_uuid_function *uuid_cb)
{
	struct lttng_ust_trace_clock *ltc = CMM_LOAD_SHARED(lttng_ust_trace_clock);

	if (caa_likely(!ltc)) {
		*uuid_cb = &trace_clock_uuid_monotonic;
	} else {
		cmm_read_barrier_depends();     /* load ltc before content */
		*uuid_cb = ltc->uuid;
	}
	return 0;
}

int lttng_ust_trace_clock_set_name_cb(lttng_ust_clock_name_function name_cb)
{
	if (CMM_LOAD_SHARED(lttng_ust_trace_clock))
		return -EBUSY;
	user_tc.name = name_cb;
	return 0;
}

int lttng_ust_trace_clock_get_name_cb(lttng_ust_clock_name_function *name_cb)
{
	struct lttng_ust_trace_clock *ltc = CMM_LOAD_SHARED(lttng_ust_trace_clock);

	if (caa_likely(!ltc)) {
		*name_cb = &trace_clock_name_monotonic;
	} else {
		cmm_read_barrier_depends();     /* load ltc before content */
		*name_cb = ltc->name;
	}
	return 0;
}

int lttng_ust_trace_clock_set_description_cb(lttng_ust_clock_description_function description_cb)
{
	if (CMM_LOAD_SHARED(lttng_ust_trace_clock))
		return -EBUSY;
	user_tc.description = description_cb;
	return 0;
}

int lttng_ust_trace_clock_get_description_cb(lttng_ust_clock_description_function *description_cb)
{
	struct lttng_ust_trace_clock *ltc = CMM_LOAD_SHARED(lttng_ust_trace_clock);

	if (caa_likely(!ltc)) {
		*description_cb = &trace_clock_description_monotonic;
	} else {
		cmm_read_barrier_depends();     /* load ltc before content */
		*description_cb = ltc->description;
	}
	return 0;
}

int lttng_ust_enable_trace_clock_override(void)
{
	if (CMM_LOAD_SHARED(lttng_ust_trace_clock))
		return -EBUSY;
	if (!user_tc.read64)
		return -EINVAL;
	if (!user_tc.freq)
		return -EINVAL;
	if (!user_tc.name)
		return -EINVAL;
	if (!user_tc.description)
		return -EINVAL;
	/* Use default uuid cb when NULL */
	cmm_smp_mb();	/* Store callbacks before trace clock */
	CMM_STORE_SHARED(lttng_ust_trace_clock, &user_tc);
	return 0;
}

void lttng_ust_clock_init(void)
{
	const char *libname;
	void (*libinit)(void);

	if (clock_handle)
		return;
	libname = lttng_ust_getenv("LTTNG_UST_CLOCK_PLUGIN");
	if (!libname)
		return;
	clock_handle = dlopen(libname, RTLD_NOW);
	if (!clock_handle) {
		PERROR("Cannot load LTTng UST clock override library %s",
			libname);
		return;
	}
	dlerror();
	libinit = (void (*)(void)) dlsym(clock_handle,
		"lttng_ust_clock_plugin_init");
	if (!libinit) {
		PERROR("Cannot find LTTng UST clock override library %s initialization function lttng_ust_clock_plugin_init()",
			libname);
		return;
	}
	libinit();
}
