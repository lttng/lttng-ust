/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2011 Julien Desfossez <julien.desfossez@polymtl.ca>
 * Copyright (C) 2011-2013 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _LTTNG_UST_CTL_PRIVATE_H
#define _LTTNG_UST_CTL_PRIVATE_H

#include <lttng/ust-ctl.h>

/*
 * Map channel lttng_ust_shm_handle and add streams. Typically performed
 * by the application to map the objects into its memory space.
 */
struct lttng_ust_shm_handle *
	ustctl_map_channel(struct lttng_ust_object_data *chan_data);
int ustctl_add_stream(struct lttng_ust_shm_handle *lttng_ust_shm_handle,
		struct lttng_ust_object_data *stream_data);
/*
 * Note: the lttng_ust_object_data from which the lttng_ust_shm_handle
 * is derived can only be released after unmapping the handle.
 */
void ustctl_unmap_channel(struct lttng_ust_shm_handle *lttng_ust_shm_handle);

#endif /* _LTTNG_UST_CTL_PRIVATE_H */
