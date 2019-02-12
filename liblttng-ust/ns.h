#ifndef _LTTNG_NS_H
#define _LTTNG_NS_H

/*
 * Copyright (c) 2019 - Michael Jeanson <mjeanson@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; only
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */


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
