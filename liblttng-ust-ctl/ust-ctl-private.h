/*
 * Copyright (C) 2011 - Julien Desfossez <julien.desfossez@polymtl.ca>
 * Copyright (C) 2011-2013 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License only.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
