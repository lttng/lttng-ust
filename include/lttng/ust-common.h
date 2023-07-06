// SPDX-FileCopyrightText: 2021 Michael Jeanson <mjeanson@efficios.com>
//
// SPDX-License-Identifier: MIT

/*
 * Public symbols of liblttng-ust-common.so
 */

#ifndef _LTTNG_UST_COMMON_H
#define _LTTNG_UST_COMMON_H

/*
 * The liblttng-ust-common constructor is public so it can be called in the
 * constructors of client libraries since there is no reliable way to guarantee
 * the execution order of constructors across shared library.
 */
void lttng_ust_common_ctor(void)
	__attribute__((constructor));

void lttng_ust_common_alloc_tls(void);

#endif
