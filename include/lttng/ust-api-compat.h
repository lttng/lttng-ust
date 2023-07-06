// SPDX-FileCopyrightText: 2021 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
//
// SPDX-License-Identifier: MIT

/*
 * LTTng-UST API compatibility header
 */

#ifndef _LTTNG_UST_API_COMPAT_H
#define _LTTNG_UST_API_COMPAT_H

/*
 * The compat API version controls backward API compatibility at the
 * source-code level.
 *
 * In order to disable compatibility API for a range of API versions, define
 * LTTNG_UST_COMPAT_API_VERSION to the oldest API version for which to provide
 * compatibility.
 *
 * If LTTNG_UST_COMPAT_API_VERSION is undefined, API compatibility for
 * all API versions is provided.
 * If LTTNG_UST_COMPAT_API_VERSION is defined to N, API compatibility
 * for versions N or higher is provided, thus not defining compatibility macros
 * for versions lower than N.
 */

#ifndef LTTNG_UST_COMPAT_API_VERSION
#define LTTNG_UST_COMPAT_API_VERSION 0
#endif

#define LTTNG_UST_COMPAT_API(major)	\
	(LTTNG_UST_COMPAT_API_VERSION <= (major))

#endif /* _LTTNG_UST_API_COMPAT_H */
