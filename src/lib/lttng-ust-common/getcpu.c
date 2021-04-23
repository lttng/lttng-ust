/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#define _LGPL_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <urcu/system.h>
#include <urcu/arch.h>

#include "common/getcpu.h"
#include "common/getenv.h"
#include "common/logging.h"

#include "lib/lttng-ust-common/getcpu.h"

/* Function pointer to the current getcpu callback. */
int (*lttng_ust_get_cpu_sym)(void);

static
void *getcpu_plugin_handle;

/*
 * Override the user provided getcpu implementation.
 */
int lttng_ust_getcpu_override(int (*getcpu)(void))
{
	CMM_STORE_SHARED(lttng_ust_get_cpu_sym, getcpu);
	return 0;
}

/*
 * Initialize the getcpu plugin if it's present.
 */
void lttng_ust_getcpu_plugin_init(void)
{
	const char *libname;
	void (*getcpu_plugin_init)(void);

	/* If a plugin is already loaded, do nothing. */
	if (getcpu_plugin_handle)
		return;

	/*
	 * If the LTTNG_UST_GETCPU_PLUGIN environment variable is undefined, do
	 * nothing.
	 */
	libname = lttng_ust_getenv("LTTNG_UST_GETCPU_PLUGIN");
	if (!libname)
		return;

	/*
	 * Thy to dlopen the getcpu plugin shared object specified in
	 * LTTNG_UST_GETCPU_PLUGIN.
	 */
	getcpu_plugin_handle = dlopen(libname, RTLD_NOW);
	if (!getcpu_plugin_handle) {
		PERROR("Cannot load LTTng UST getcpu override library %s",
			libname);
		return;
	}
	dlerror();

	/* Locate the getcpu plugin init function in the shared object. */
	getcpu_plugin_init = (void (*)(void)) dlsym(getcpu_plugin_handle,
		"lttng_ust_getcpu_plugin_init");
	if (!getcpu_plugin_init) {
		PERROR("Cannot find LTTng UST getcpu override library %s initialization function lttng_ust_getcpu_plugin_init()",
			libname);
		return;
	}

	/* Run the user provided getcpu plugin init function. */
	getcpu_plugin_init();
}
