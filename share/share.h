#ifndef UST_SHARE_H
#define UST_SHARE_H

#include <unistd.h>
#include <errno.h>

/* This write is patient because it restarts if it was incomplete.
 */

static inline ssize_t patient_write(int fd, const void *buf, size_t count)
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

#endif /* UST_SHARE_H */
