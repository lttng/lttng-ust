// SPDX-FileCopyrightText: 2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
//
// SPDX-License-Identifier: LGPL-2.1-only

#ifndef LTTNG_UST_GETCPU_H
#define LTTNG_UST_GETCPU_H

#include <stdint.h>
#include <stddef.h>

/*
 * Set getcpu override read callback. This callback should return the
 * current CPU number.
 */
int lttng_ust_getcpu_override(int (*getcpu)(void));

#endif /* LTTNG_UST_GETCPU_H */
