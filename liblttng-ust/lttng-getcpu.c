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

#define _GNU_SOURCE
#define _LGPL_SOURCE
#include <error.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <usterr-signal-safe.h>
#include <lttng/ust-getcpu.h>
#include <urcu/system.h>
#include <urcu/arch.h>

#include "getenv.h"
#include "../libringbuffer/getcpu.h"

int (*lttng_get_cpu)(void);

static
void *getcpu_handle;

int lttng_ust_getcpu_override(int (*getcpu)(void))
{
	CMM_STORE_SHARED(lttng_get_cpu, getcpu);
	return 0;
}

void lttng_ust_getcpu_init(void)
{
	const char *libname;
	void (*libinit)(void);

	if (getcpu_handle)
		return;
	libname = lttng_getenv("LTTNG_UST_GETCPU_PLUGIN");
	if (!libname)
		return;
	getcpu_handle = dlopen(libname, RTLD_NOW);
	if (!getcpu_handle) {
		PERROR("Cannot load LTTng UST getcpu override library %s",
			libname);
		return;
	}
	dlerror();
	libinit = (void (*)(void)) dlsym(getcpu_handle,
		"lttng_ust_getcpu_plugin_init");
	if (!libinit) {
		PERROR("Cannot find LTTng UST getcpu override library %s initialization function lttng_ust_getcpu_plugin_init()",
			libname);
		return;
	}
	libinit();
}
