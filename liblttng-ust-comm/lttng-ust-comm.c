/*
 * Copyright (C)  2011 - David Goulet <david.goulet@polymtl.ca>
 * Copyright (C)  2011-2013 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#define _GNU_SOURCE
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>

#include <ust-comm.h>
#include <helper.h>
#include <lttng/ust-error.h>

#define USTCOMM_CODE_OFFSET(code)	\
	(code == LTTNG_UST_OK ? 0 : (code - LTTNG_UST_ERR + 1))

#define USTCOMM_MAX_SEND_FDS	4

/*
 * Human readable error message.
 */
static const char *ustcomm_readable_code[] = {
	[ USTCOMM_CODE_OFFSET(LTTNG_UST_OK) ] = "Success",
	[ USTCOMM_CODE_OFFSET(LTTNG_UST_ERR) ] = "Unknown error",
	[ USTCOMM_CODE_OFFSET(LTTNG_UST_ERR_NOENT) ] = "No entry",
	[ USTCOMM_CODE_OFFSET(LTTNG_UST_ERR_EXIST) ] = "Object already exists",
	[ USTCOMM_CODE_OFFSET(LTTNG_UST_ERR_INVAL) ] = "Invalid argument",
	[ USTCOMM_CODE_OFFSET(LTTNG_UST_ERR_PERM) ] = "Permission denied",
	[ USTCOMM_CODE_OFFSET(LTTNG_UST_ERR_NOSYS) ] = "Not implemented",
	[ USTCOMM_CODE_OFFSET(LTTNG_UST_ERR_EXITING) ] = "Process is exiting",
};

/*
 * lttng_ust_strerror
 *
 * Receives positive error value.
 * Return ptr to string representing a human readable
 * error code from the ustcomm_return_code enum.
 */
const char *lttng_ust_strerror(int code)
{
	if (code == LTTNG_UST_OK)
		return ustcomm_readable_code[USTCOMM_CODE_OFFSET(code)];
	if (code < LTTNG_UST_ERR)
		return strerror(code);
	if (code >= LTTNG_UST_ERR_NR)
		code = LTTNG_UST_ERR;
	return ustcomm_readable_code[USTCOMM_CODE_OFFSET(code)];

}

/*
 * ustcomm_connect_unix_sock
 *
 * Connect to unix socket using the path name.
 */
int ustcomm_connect_unix_sock(const char *pathname)
{
	struct sockaddr_un sun;
	int fd, ret;

	/*
	 * libust threads require the close-on-exec flag for all
	 * resources so it does not leak file descriptors upon exec.
	 */
	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		ret = -errno;
		goto error;
	}
	ret = fcntl(fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		perror("fcntl");
		ret = -errno;
		goto error_fcntl;
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, pathname, sizeof(sun.sun_path));
	sun.sun_path[sizeof(sun.sun_path) - 1] = '\0';

	ret = connect(fd, (struct sockaddr *) &sun, sizeof(sun));
	if (ret < 0) {
		/*
		 * Don't print message on connect error, because connect
		 * is used in normal execution to detect if sessiond is
		 * alive.
		 */
		ret = -errno;
		goto error_connect;
	}

	return fd;

error_connect:
error_fcntl:
	{
		int closeret;

		closeret = close(fd);
		if (closeret)
			perror("close");
	}
error:
	return ret;
}

/*
 * ustcomm_accept_unix_sock
 *
 * Do an accept(2) on the sock and return the
 * new file descriptor. The socket MUST be bind(2) before.
 */
int ustcomm_accept_unix_sock(int sock)
{
	int new_fd;
	struct sockaddr_un sun;
	socklen_t len = 0;

	/* Blocking call */
	new_fd = accept(sock, (struct sockaddr *) &sun, &len);
	if (new_fd < 0) {
		perror("accept");
		return -errno;
	}
	return new_fd;
}

/*
 * ustcomm_create_unix_sock
 *
 * Creates a AF_UNIX local socket using pathname
 * bind the socket upon creation and return the fd.
 */
int ustcomm_create_unix_sock(const char *pathname)
{
	struct sockaddr_un sun;
	int fd, ret;

	/* Create server socket */
	if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		ret = -errno;
		goto error;
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, pathname, sizeof(sun.sun_path));
	sun.sun_path[sizeof(sun.sun_path) - 1] = '\0';

	/* Unlink the old file if present */
	(void) unlink(pathname);
	ret = bind(fd, (struct sockaddr *) &sun, sizeof(sun));
	if (ret < 0) {
		perror("bind");
		ret = -errno;
		goto error_close;
	}

	return fd;

error_close:
	{
		int closeret;

		closeret = close(fd);
		if (closeret) {
			perror("close");
		}
	}
error:
	return ret;
}

/*
 * ustcomm_listen_unix_sock
 *
 * Make the socket listen using LTTNG_UST_COMM_MAX_LISTEN.
 */
int ustcomm_listen_unix_sock(int sock)
{
	int ret;

	ret = listen(sock, LTTNG_UST_COMM_MAX_LISTEN);
	if (ret < 0) {
		ret = -errno;
		perror("listen");
	}

	return ret;
}

/*
 * ustcomm_close_unix_sock
 *
 * Shutdown cleanly a unix socket.
 */
int ustcomm_close_unix_sock(int sock)
{
	int ret;

	ret = close(sock);
	if (ret < 0) {
		perror("close");
		ret = -errno;
	}

	return ret;
}

/*
 * ustcomm_recv_unix_sock
 *
 * Receive data of size len in put that data into
 * the buf param. Using recvmsg API.
 * Return the size of received data.
 * Return 0 on orderly shutdown.
 */
ssize_t ustcomm_recv_unix_sock(int sock, void *buf, size_t len)
{
	struct msghdr msg;
	struct iovec iov[1];
	ssize_t ret;

	memset(&msg, 0, sizeof(msg));

	iov[0].iov_base = buf;
	iov[0].iov_len = len;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	do {
		ret = recvmsg(sock, &msg, 0);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0) {
		int shutret;

		if (errno != EPIPE && errno != ECONNRESET)
			perror("recvmsg");
		ret = -errno;

		shutret = shutdown(sock, SHUT_RDWR);
		if (shutret)
			fprintf(stderr, "Socket shutdown error");
	}

	return ret;
}

/*
 * ustcomm_send_unix_sock
 *
 * Send buf data of size len. Using sendmsg API.
 * Return the size of sent data.
 */
ssize_t ustcomm_send_unix_sock(int sock, void *buf, size_t len)
{
	struct msghdr msg;
	struct iovec iov[1];
	ssize_t ret;

	memset(&msg, 0, sizeof(msg));

	iov[0].iov_base = buf;
	iov[0].iov_len = len;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	/*
	 * Using the MSG_NOSIGNAL when sending data from sessiond to
	 * libust, so libust does not receive an unhandled SIGPIPE or
	 * SIGURG. The sessiond receiver side can be made more resilient
	 * by ignoring SIGPIPE, but we don't have this luxury on the
	 * libust side.
	 */
	do {
		ret = sendmsg(sock, &msg, MSG_NOSIGNAL);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0) {
		int shutret;

		if (errno != EPIPE && errno != ECONNRESET)
			perror("sendmsg");
		ret = -errno;

		shutret = shutdown(sock, SHUT_RDWR);
		if (shutret)
			fprintf(stderr, "Socket shutdown error");
	}

	return ret;
}

/*
 * Send a message accompanied by fd(s) over a unix socket.
 *
 * Returns the size of data sent, or negative error value.
 */
ssize_t ustcomm_send_fds_unix_sock(int sock, int *fds, size_t nb_fd)
{
	struct msghdr msg;
	struct cmsghdr *cmptr;
	struct iovec iov[1];
	ssize_t ret = -1;
	unsigned int sizeof_fds = nb_fd * sizeof(int);
	char tmp[CMSG_SPACE(sizeof_fds)];
	char dummy = 0;

	memset(&msg, 0, sizeof(msg));
	memset(tmp, 0, CMSG_SPACE(sizeof_fds) * sizeof(char));

	if (nb_fd > USTCOMM_MAX_SEND_FDS)
		return -EINVAL;

	msg.msg_control = (caddr_t)tmp;
	msg.msg_controllen = CMSG_LEN(sizeof_fds);

	cmptr = CMSG_FIRSTHDR(&msg);
	cmptr->cmsg_level = SOL_SOCKET;
	cmptr->cmsg_type = SCM_RIGHTS;
	cmptr->cmsg_len = CMSG_LEN(sizeof_fds);
	memcpy(CMSG_DATA(cmptr), fds, sizeof_fds);
	/* Sum of the length of all control messages in the buffer: */
	msg.msg_controllen = cmptr->cmsg_len;

	iov[0].iov_base = &dummy;
	iov[0].iov_len = 1;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	do {
		ret = sendmsg(sock, &msg, 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		/*
		 * We consider EPIPE and ECONNRESET as expected.
		 */
		if (errno != EPIPE && errno != ECONNRESET) {
			perror("sendmsg");
		}
	}
	return ret;
}

/*
 * Recv a message accompanied by fd(s) from a unix socket.
 *
 * Returns the size of received data, or negative error value.
 *
 * Expect at most "nb_fd" file descriptors. Returns the number of fd
 * actually received in nb_fd.
 * Returns -EPIPE on orderly shutdown.
 */
ssize_t ustcomm_recv_fds_unix_sock(int sock, int *fds, size_t nb_fd)
{
	struct iovec iov[1];
	ssize_t ret = 0;
	struct cmsghdr *cmsg;
	size_t sizeof_fds = nb_fd * sizeof(int);
	char recv_fd[CMSG_SPACE(sizeof_fds)];
	struct msghdr msg;
	char dummy;

	memset(&msg, 0, sizeof(msg));

	/* Prepare to receive the structures */
	iov[0].iov_base = &dummy;
	iov[0].iov_len = 1;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_control = recv_fd;
	msg.msg_controllen = sizeof(recv_fd);

	do {
		ret = recvmsg(sock, &msg, 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		if (errno != EPIPE && errno != ECONNRESET) {
			perror("recvmsg fds");
		}
		if (errno == EPIPE || errno == ECONNRESET)
			ret = -errno;
		goto end;
	}
	if (ret == 0) {
		/* orderly shutdown */
		ret = -EPIPE;
		goto end;
	}
	if (ret != 1) {
		fprintf(stderr, "Error: Received %zd bytes, expected %d\n",
				ret, 1);
		goto end;
	}
	if (msg.msg_flags & MSG_CTRUNC) {
		fprintf(stderr, "Error: Control message truncated.\n");
		ret = -1;
		goto end;
	}
	cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg) {
		fprintf(stderr, "Error: Invalid control message header\n");
		ret = -1;
		goto end;
	}
	if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
		fprintf(stderr, "Didn't received any fd\n");
		ret = -1;
		goto end;
	}
	if (cmsg->cmsg_len != CMSG_LEN(sizeof_fds)) {
		fprintf(stderr, "Error: Received %zu bytes of ancillary data, expected %zu\n",
				(size_t) cmsg->cmsg_len, (size_t) CMSG_LEN(sizeof_fds));
		ret = -1;
		goto end;
	}
	memcpy(fds, CMSG_DATA(cmsg), sizeof_fds);
	ret = sizeof_fds;
end:
	return ret;
}

int ustcomm_send_app_msg(int sock, struct ustcomm_ust_msg *lum)
{
	ssize_t len;

	len = ustcomm_send_unix_sock(sock, lum, sizeof(*lum));
	switch (len) {
	case sizeof(*lum):
		break;
	default:
		if (len < 0) {
			return len;
		} else {
			fprintf(stderr, "incorrect message size: %zd\n", len);
			return -EINVAL;
		}
	}
	return 0;
}

int ustcomm_recv_app_reply(int sock, struct ustcomm_ust_reply *lur,
			  uint32_t expected_handle, uint32_t expected_cmd)
{
	ssize_t len;

	memset(lur, 0, sizeof(*lur));
	len = ustcomm_recv_unix_sock(sock, lur, sizeof(*lur));
	switch (len) {
	case 0:	/* orderly shutdown */
		return -EPIPE;
	case sizeof(*lur):
		if (lur->handle != expected_handle) {
			fprintf(stderr, "Unexpected result message handle: "
				"expected: %u vs received: %u\n",
				expected_handle, lur->handle);
			return -EINVAL;
		}
		if (lur->cmd != expected_cmd) {
			fprintf(stderr, "Unexpected result message command "
				"expected: %u vs received: %u\n",
				expected_cmd, lur->cmd);
			return -EINVAL;
		}
		return lur->ret_code;
	default:
		if (len < 0) {
			/* Transport level error */
			if (errno == EPIPE || errno == ECONNRESET)
				len = -errno;
			return len;
		} else {
			fprintf(stderr, "incorrect message size: %zd\n", len);
			return len;
		}
	}
}

int ustcomm_send_app_cmd(int sock,
			struct ustcomm_ust_msg *lum,
			struct ustcomm_ust_reply *lur)
{
	int ret;

	ret = ustcomm_send_app_msg(sock, lum);
	if (ret)
		return ret;
	ret = ustcomm_recv_app_reply(sock, lur, lum->handle, lum->cmd);
	if (ret > 0)
		return -EIO;
	return ret;
}

/*
 * chan_data is allocated internally if this function returns the
 * expected var_len.
 */
ssize_t ustcomm_recv_channel_from_sessiond(int sock,
		void **_chan_data, uint64_t var_len)
{
	void *chan_data;
	ssize_t len;

	if (var_len > LTTNG_UST_CHANNEL_DATA_MAX_LEN) {
		len = -EINVAL;
		goto error_check;
	}
	/* Receive variable length data */
	chan_data = zmalloc(var_len);
	if (!chan_data) {
		len = -ENOMEM;
		goto error_alloc;
	}
	len = ustcomm_recv_unix_sock(sock, chan_data, var_len);
	if (len != var_len) {
		goto error_recv;
	}
	*_chan_data = chan_data;
	return len;

error_recv:
	free(chan_data);
error_alloc:
error_check:
	return len;
}

int ustcomm_recv_stream_from_sessiond(int sock,
		uint64_t *memory_map_size,
		int *shm_fd, int *wakeup_fd)
{
	ssize_t len;
	int ret;
	int fds[2];

	/* recv shm fd and wakeup fd */
	len = ustcomm_recv_fds_unix_sock(sock, fds, 2);
	if (len <= 0) {
		if (len < 0) {
			ret = len;
			goto error;
		} else {
			ret = -EIO;
			goto error;
		}
	}
	*shm_fd = fds[0];
	*wakeup_fd = fds[1];
	return 0;

error:
	return ret;
}
