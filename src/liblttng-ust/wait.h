/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _UST_WAIT_H
#define _UST_WAIT_H

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
