// SPDX-FileCopyrightText: 2020 Michael Jeanson <mjeanson@efficios.com>
//
// SPDX-License-Identifier: MIT

/*
 * Public symbols of liblttng-ust-libc-wrapper.so
 */

#ifndef _LTTNG_UST_LIBC_WRAPPER_H
#define _LTTNG_UST_LIBC_WRAPPER_H

/*
 * This is the constructor for the malloc part of the libc wrapper. It is
 * publicly exposed because the malloc override needs to be initialized before
 * the process becomes multithreaded and thus must happen before the main
 * constructor of liblttng-ust starts threads. Since there is no reliable way
 * to guarantee the execution order of constructors across shared library, the
 * liblttng-ust constructor has to call the malloc constructor before starting
 * any thread. This is achieved by having a weak public version of this
 * function in liblttng-ust that is overridden by the one in
 * liblttng-ust-wrapper-libc when it's preloaded.
 */
void lttng_ust_libc_wrapper_malloc_ctor(void)
	__attribute__((constructor));

#endif
