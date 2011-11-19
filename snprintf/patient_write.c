/*
 * Copyright (C) 2009  Pierre-Marc Fournier
 * Copyright (C) 2011  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
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

/* write() */
#include <unistd.h>

/* send() */
#include <sys/types.h>
#include <sys/socket.h>

#include <errno.h>

#include <share.h>

/*
 * This write is patient because it restarts if it was incomplete.
 */

ssize_t patient_write(int fd, const void *buf, size_t count)
{
	const char *bufc = (const char *) buf;
	int result;

	for(;;) {
		result = write(fd, bufc, count);
		if (result == -1 && errno == EINTR) {
			continue;
		}
		if (result <= 0) {
			return result;
		}
		count -= result;
		bufc += result;

		if (count == 0) {
			break;
		}
	}

	return bufc-(const char *)buf;
}

ssize_t patient_send(int fd, const void *buf, size_t count, int flags)
{
	const char *bufc = (const char *) buf;
	int result;

	for(;;) {
		result = send(fd, bufc, count, flags);
		if (result == -1 && errno == EINTR) {
			continue;
		}
		if (result <= 0) {
			return result;
		}
		count -= result;
		bufc += result;

		if (count == 0) {
			break;
		}
	}

	return bufc - (const char *) buf;
}
