/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2019 Michael Jeanson <mjeanson@efficios.com>
 */

#ifndef _LTTNG_NS_H
#define _LTTNG_NS_H

/*
 * The lowest valid inode number that can be allocated in the proc filesystem
 * is 0xF0000000. Any number below can be used internally as an error code.
 *
 * Zero is used in the kernel as an error code, it's the value we will return
 * when we fail to read the proper inode number.
 *
 * One is used internally to identify an uninitialized cache entry, it should
 * never be returned.
 */

enum ns_ino_state {
	NS_INO_UNAVAILABLE	= 0x0,
	NS_INO_UNINITIALIZED	= 0x1,
	NS_INO_MIN		= 0xF0000000,
};

#endif /* _LTTNG_NS_H */
