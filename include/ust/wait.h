#ifndef _UST_WAIT_H
#define _UST_WAIT_H

/*
 * Copyright (C) 2011  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; version 2.1 of
 * the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <poll.h>

/*
 * Wait until "cond" gets true or timeout (in ms).
 */
#define wait_cond_interruptible_timeout(_cond, _timeout)	\
	({							\
		int __ret = 0, __pollret;			\
		int __timeout = _timeout;			\
								\
		for (;;) {					\
			if (_cond)				\
				break;				\
			if (__timeout <= 0) {			\
				__ret = -ETIMEDOUT;		\
				break;				\
			}					\
			__pollret = poll(NULL, 0, 10);	/* wait 10ms */	\
			if (__pollret < 0) {			\
				__ret = -errno;			\
				break;				\
			}					\
			__timeout -= 10;			\
		}						\
		__ret;						\
	})


#endif /* _UST_WAIT_H */
