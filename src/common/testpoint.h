/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright (C) 2025 Olivier Dion <odion@efficios.com>
 */

#ifndef _UST_COMMON_TESTPOINT_H
#define _UST_COMMON_TESTPOINT_H

/*
 * A test point is a label to some interesting point in the code flow.
 *
 * Typically placed after an observable side-effect, testpoints can be used to
 * force race conditions to happen with an external debugger.
 */
#define TESTPOINT(label)						\
	__asm__ volatile (".local lttng_ust_testpoint_" label ".%=\n\t"	\
			"lttng_ust_testpoint_" label ".%= =." : : :)

#endif	/* _UST_COMMON_TESTPOINT_H */
