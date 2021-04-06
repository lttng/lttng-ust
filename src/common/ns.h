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

/*
 * The longest possible namespace proc path is with the cgroup ns
 * and the maximum theoretical linux pid of 536870912 :
 *
 *  /proc/self/task/536870912/ns/cgroup
 */
#define LTTNG_PROC_NS_PATH_MAX 40

#endif /* _LTTNG_NS_H */
