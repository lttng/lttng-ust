#ifndef UST_SHARE_H
#define UST_SHARE_H

/* write() */
#include <unistd.h>

/* send() */
#include <sys/types.h>
#include <sys/socket.h>

#include <errno.h>

/* This write is patient because it restarts if it was incomplete.
 */

static __inline__ ssize_t patient_write(int fd, const void *buf, size_t count)
{
	const char *bufc = (const char *) buf;
	int result;

	for(;;) {
		result = write(fd, bufc, count);
		if(result == -1 && errno == EINTR) {
			continue;
		}
		if(result <= 0) {
			return result;
		}
		count -= result;
		bufc += result;

		if(count == 0) {
			break;
		}
	}

	return bufc-(const char *)buf;
}

static __inline__ ssize_t patient_send(int fd, const void *buf, size_t count, int flags)
{
	const char *bufc = (const char *) buf;
	int result;

	for(;;) {
		result = send(fd, bufc, count, flags);
		if(result == -1 && errno == EINTR) {
			continue;
		}
		if(result <= 0) {
			return result;
		}
		count -= result;
		bufc += result;

		if(count == 0) {
			break;
		}
	}

	return bufc-(const char *)buf;
}

#endif /* UST_SHARE_H */
