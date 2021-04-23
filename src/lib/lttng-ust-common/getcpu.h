/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _LTTNG_UST_COMMON_GETCPU_H
#define _LTTNG_UST_COMMON_GETCPU_H

/*
 * Initialize the getcpu plugin if it's present.
 */
void lttng_ust_getcpu_plugin_init(void)
	__attribute__((visibility("hidden")));


#endif /* _LTTNG_UST_COMMON_GETCPU_H */
