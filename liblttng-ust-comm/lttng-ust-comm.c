/*
 * Copyright (C)  2011 - David Goulet <david.goulet@polymtl.ca>
 * Copyright (C)  2011 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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
#include <lttng/ust-error.h>

#define USTCOMM_CODE_OFFSET(code)	\
	(code == LTTNG_UST_OK ? 0 : (code - LTTNG_UST_ERR + 1))

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
 * 	ustcomm_connect_unix_sock
 *
 * 	Connect to unix socket using the path name.
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
 * 	ustcomm_accept_unix_sock
 *
 *	Do an accept(2) on the sock and return the
 *	new file descriptor. The socket MUST be bind(2) before.
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
 * 	ustcomm_create_unix_sock
 *
 * 	Creates a AF_UNIX local socket using pathname
 * 	bind the socket upon creation and return the fd.
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
 * 	ustcomm_listen_unix_sock
 *
 * 	Make the socket listen using LTTNG_UST_COMM_MAX_LISTEN.
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
 * 	ustcomm_recv_unix_sock
 *
 *  Receive data of size len in put that data into
 *  the buf param. Using recvmsg API.
 *  Return the size of received data.
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

		if (errno != EPIPE)
			perror("recvmsg");
		ret = -errno;

		shutret = shutdown(sock, SHUT_RDWR);
		if (shutret)
			fprintf(stderr, "Socket shutdown error");
	}

	return ret;
}

/*
 * 	ustcomm_send_unix_sock
 *
 * 	Send buf data of size len. Using sendmsg API.
 * 	Return the size of sent data.
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

		if (errno != EPIPE)
			perror("recvmsg");
		ret = -errno;

		shutret = shutdown(sock, SHUT_RDWR);
		if (shutret)
			fprintf(stderr, "Socket shutdown error");
	}

	return ret;
}

/*
 *  ustcomm_close_unix_sock
 *
 *  Shutdown cleanly a unix socket.
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
 *  ustcomm_send_fds_unix_sock
 *
 *  Send multiple fds on a unix socket.
 */
ssize_t ustcomm_send_fds_unix_sock(int sock, void *buf, int *fds, size_t nb_fd, size_t len)
{
	struct msghdr msg;
	struct cmsghdr *cmptr;
	struct iovec iov[1];
	ssize_t ret = -1;
	unsigned int sizeof_fds = nb_fd * sizeof(int);
	char tmp[CMSG_SPACE(sizeof_fds)];

	memset(&msg, 0, sizeof(msg));

	/*
	 * Note: we currently only support sending a single FD per
	 * message.
	 */
	assert(nb_fd == 1);

	msg.msg_control = (caddr_t)tmp;
	msg.msg_controllen = CMSG_LEN(sizeof_fds);

	cmptr = CMSG_FIRSTHDR(&msg);
	cmptr->cmsg_level = SOL_SOCKET;
	cmptr->cmsg_type = SCM_RIGHTS;
	cmptr->cmsg_len = CMSG_LEN(sizeof_fds);
	memcpy(CMSG_DATA(cmptr), fds, sizeof_fds);
	/* Sum of the length of all control messages in the buffer: */
	msg.msg_controllen = cmptr->cmsg_len;

	iov[0].iov_base = buf;
	iov[0].iov_len = len;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	do {
		ret = sendmsg(sock, &msg, MSG_NOSIGNAL);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0) {
		int shutret;

		if (errno != EPIPE)
			perror("recvmsg");
		ret = -errno;

		shutret = shutdown(sock, SHUT_RDWR);
		if (shutret)
			fprintf(stderr, "Socket shutdown error");
	}

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
			if (len == -ECONNRESET)
				fprintf(stderr, "remote end closed connection\n");
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
		return -EINVAL;
	case sizeof(*lur):
		if (lur->handle != expected_handle) {
			fprintf(stderr, "Unexpected result message handle\n");
			return -EINVAL;
		}
		if (lur->cmd != expected_cmd) {
			fprintf(stderr, "Unexpected result message command\n");
			return -EINVAL;
		}
		return lur->ret_code;
	default:
		if (len < 0) {
			/* Transport level error */
			if (len == -ECONNRESET)
				fprintf(stderr, "remote end closed connection\n");
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
	return ustcomm_recv_app_reply(sock, lur, lum->handle, lum->cmd);
}

/*
 * Receives a single fd from socket.
 *
 * Returns negative error value on error, or file descriptor number on
 * success.
 */
int ustcomm_recv_fd(int sock)
{
	struct iovec iov[1];
	int ret = 0;
	int data_fd;
	struct cmsghdr *cmsg;
	char recv_fd[CMSG_SPACE(sizeof(int))];
	struct msghdr msg;
	union {
		unsigned char vc[4];
		int vi;
	} tmp;
	int i;

	memset(&msg, 0, sizeof(msg));

	/* Prepare to receive the structures */
	iov[0].iov_base = &data_fd;
	iov[0].iov_len = sizeof(data_fd);
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_control = recv_fd;
	msg.msg_controllen = sizeof(recv_fd);

	do {
		ret = recvmsg(sock, &msg, 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		if (errno != EPIPE) {
			perror("recvmsg");
		}
		ret = -errno;
		goto end;
	}
	if (ret != sizeof(data_fd)) {
		fprintf(stderr, "Received %d bytes, expected %zd", ret, sizeof(data_fd));
		ret = -EINVAL;
		goto end;
	}
	cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg) {
		fprintf(stderr, "Invalid control message header\n");
		ret = -EINVAL;
		goto end;
	}
	if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
		fprintf(stderr, "Didn't received any fd\n");
		ret = -EINVAL;
		goto end;
	}
	/* this is our fd */
	for (i = 0; i < sizeof(int); i++)
		tmp.vc[i] = CMSG_DATA(cmsg)[i];
	ret = tmp.vi;
	/*
	 * Useful for fd leak debug.
	 * fprintf(stderr, "received fd %d\n", ret);
	 */
end:
	if (ret < 0) {
		int shutret;

		shutret = shutdown(sock, SHUT_RDWR);
		if (shutret)
			fprintf(stderr, "Socket shutdown error");
	}
	return ret;
}
