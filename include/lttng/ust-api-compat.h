/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2021 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng-UST API compatibility header
 */

#ifndef _LTTNG_UST_API_COMPAT_H
#define _LTTNG_UST_API_COMPAT_H

/*
 * In order to disable compatibility API for a range of soname major
 * versions, define LTTNG_UST_COMPAT_API_VERSION to the oldest major
 * version API for which to provide compatibility.
 *
 * If LTTNG_UST_COMPAT_API_VERSION is undefined, API compatibility for
 * all API versions is provided.
 * If LTTNG_UST_COMPAT_API_VERSION is defined to N, API compatibility
 * for soname N or higher is provided, leaving out (not compiling)
 * compatibility for soname lower than N.
 */

#ifndef LTTNG_UST_COMPAT_API_VERSION
#define LTTNG_UST_COMPAT_API_VERSION 0
#endif

#define LTTNG_UST_COMPAT_API(major)	\
	(LTTNG_UST_COMPAT_API_VERSION <= (major))

#endif /* _LTTNG_UST_API_COMPAT_H */
