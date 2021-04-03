/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2016 Raphaël Beamonte <raphael.beamonte@gmail.com>
 * Copyright (C) 2020 Michael Jeanson <mjeanson@efficios.com>
 */

#ifndef _UST_COMMON_PROCNAME_H
#define _UST_COMMON_PROCNAME_H

#include <string.h>
#include <lttng/ust-abi.h>

#include "common/compat/pthread.h"

#define LTTNG_UST_PROCNAME_SUFFIX "-ust"

/*
 * If a pthread setname/set_name function is available, declare
 * the setustprocname() function that will add '-ust' to the end
 * of the current process name, while truncating it if needed.
 */
static inline
int lttng_ust_setustprocname(void)
{
	int ret = 0, len;
	char name[LTTNG_UST_ABI_PROCNAME_LEN];
	int limit = LTTNG_UST_ABI_PROCNAME_LEN - strlen(LTTNG_UST_PROCNAME_SUFFIX) - 1;

	/*
	 * Get the current thread name.
	 */
	ret = lttng_pthread_getname_np(name, LTTNG_UST_ABI_PROCNAME_LEN);
	if (ret) {
		goto error;
	}

	len = strlen(name);
	if (len > limit) {
		len = limit;
	}

	ret = sprintf(name + len, LTTNG_UST_PROCNAME_SUFFIX);
	if (ret != strlen(LTTNG_UST_PROCNAME_SUFFIX)) {
		goto error;
	}

	ret = lttng_pthread_setname_np(name);

error:
	return ret;
}

#endif /* _UST_COMMON_PROCNAME_H */
