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

#include <ust-comm.h>

/*
 * Human readable error message.
 */
static const char *ustcomm_readable_code[] = {
	[ USTCOMM_ERR_INDEX(USTCOMM_ERR) ] = "Unknown error",
	[ USTCOMM_ERR_INDEX(USTCOMM_UND) ] = "Undefined command",
	[ USTCOMM_ERR_INDEX(USTCOMM_NOT_IMPLEMENTED) ] = "Not implemented",
	[ USTCOMM_ERR_INDEX(USTCOMM_UNKNOWN_DOMAIN) ] = "Unknown tracing domain",
	[ USTCOMM_ERR_INDEX(USTCOMM_NO_SESSION) ] = "No session found",
	[ USTCOMM_ERR_INDEX(USTCOMM_LIST_FAIL) ] = "Unable to list traceable apps",
	[ USTCOMM_ERR_INDEX(USTCOMM_NO_APPS) ] = "No traceable apps found",
	[ USTCOMM_ERR_INDEX(USTCOMM_SESS_NOT_FOUND) ] = "Session name not found",
	[ USTCOMM_ERR_INDEX(USTCOMM_NO_TRACE) ] = "No trace found",
	[ USTCOMM_ERR_INDEX(USTCOMM_FATAL) ] = "Fatal error of the session daemon",
	[ USTCOMM_ERR_INDEX(USTCOMM_CREATE_FAIL) ] = "Create trace failed",
	[ USTCOMM_ERR_INDEX(USTCOMM_START_FAIL) ] = "Start trace failed",
	[ USTCOMM_ERR_INDEX(USTCOMM_STOP_FAIL) ] = "Stop trace failed",
	[ USTCOMM_ERR_INDEX(USTCOMM_NO_TRACEABLE) ] = "App is not traceable",
	[ USTCOMM_ERR_INDEX(USTCOMM_SELECT_SESS) ] = "A session MUST be selected",
	[ USTCOMM_ERR_INDEX(USTCOMM_EXIST_SESS) ] = "Session name already exist",
	[ USTCOMM_ERR_INDEX(USTCOMM_KERN_NA) ] = "UST tracer not available",
	[ USTCOMM_ERR_INDEX(USTCOMM_KERN_EVENT_EXIST) ] = "UST event already exists",
	[ USTCOMM_ERR_INDEX(USTCOMM_KERN_SESS_FAIL) ] = "UST create session failed",
	[ USTCOMM_ERR_INDEX(USTCOMM_KERN_CHAN_FAIL) ] = "UST create channel failed",
	[ USTCOMM_ERR_INDEX(USTCOMM_KERN_CHAN_NOT_FOUND) ] = "UST channel not found",
	[ USTCOMM_ERR_INDEX(USTCOMM_KERN_CHAN_DISABLE_FAIL) ] = "Disable UST channel failed",
	[ USTCOMM_ERR_INDEX(USTCOMM_KERN_CHAN_ENABLE_FAIL) ] = "Enable UST channel failed",
	[ USTCOMM_ERR_INDEX(USTCOMM_KERN_CONTEXT_FAIL) ] = "Add UST context failed",
	[ USTCOMM_ERR_INDEX(USTCOMM_KERN_ENABLE_FAIL) ] = "Enable UST event failed",
	[ USTCOMM_ERR_INDEX(USTCOMM_KERN_DISABLE_FAIL) ] = "Disable UST event failed",
	[ USTCOMM_ERR_INDEX(USTCOMM_KERN_META_FAIL) ] = "Opening metadata failed",
	[ USTCOMM_ERR_INDEX(USTCOMM_KERN_START_FAIL) ] = "Starting UST trace failed",
	[ USTCOMM_ERR_INDEX(USTCOMM_KERN_STOP_FAIL) ] = "Stoping UST trace failed",
	[ USTCOMM_ERR_INDEX(USTCOMM_KERN_CONSUMER_FAIL) ] = "UST consumer start failed",
	[ USTCOMM_ERR_INDEX(USTCOMM_KERN_STREAM_FAIL) ] = "UST create stream failed",
	[ USTCOMM_ERR_INDEX(USTCOMM_KERN_DIR_FAIL) ] = "UST trace directory creation failed",
	[ USTCOMM_ERR_INDEX(USTCOMM_KERN_DIR_EXIST) ] = "UST trace directory already exist",
	[ USTCOMM_ERR_INDEX(USTCOMM_KERN_NO_SESSION) ] = "No UST session found",
	[ USTCOMM_ERR_INDEX(USTCOMM_KERN_LIST_FAIL) ] = "Listing UST events failed",
	[ USTCOMM_ERR_INDEX(USTCONSUMER_COMMAND_SOCK_READY) ] = "UST consumer command socket ready",
	[ USTCOMM_ERR_INDEX(USTCONSUMER_SUCCESS_RECV_FD) ] = "UST consumer success on receiving fds",
	[ USTCOMM_ERR_INDEX(USTCONSUMER_ERROR_RECV_FD) ] = "UST consumer error on receiving fds",
	[ USTCOMM_ERR_INDEX(USTCONSUMER_POLL_ERROR) ] = "UST consumer error in polling thread",
	[ USTCOMM_ERR_INDEX(USTCONSUMER_POLL_NVAL) ] = "UST consumer polling on closed fd",
	[ USTCOMM_ERR_INDEX(USTCONSUMER_POLL_HUP) ] = "UST consumer all fd hung up",
	[ USTCOMM_ERR_INDEX(USTCONSUMER_EXIT_SUCCESS) ] = "UST consumer exiting normally",
	[ USTCOMM_ERR_INDEX(USTCONSUMER_EXIT_FAILURE) ] = "UST consumer exiting on error",
	[ USTCOMM_ERR_INDEX(USTCONSUMER_OUTFD_ERROR) ] = "UST consumer error opening the tracefile",
	[ USTCOMM_ERR_INDEX(USTCONSUMER_SPLICE_EBADF) ] = "UST consumer splice EBADF",
	[ USTCOMM_ERR_INDEX(USTCONSUMER_SPLICE_EINVAL) ] = "UST consumer splice EINVAL",
	[ USTCOMM_ERR_INDEX(USTCONSUMER_SPLICE_ENOMEM) ] = "UST consumer splice ENOMEM",
	[ USTCOMM_ERR_INDEX(USTCONSUMER_SPLICE_ESPIPE) ] = "UST consumer splice ESPIPE",
	[ USTCOMM_ERR_INDEX(USTCOMM_NO_EVENT) ] = "Event not found",
};

/*
 *  lttcom_get_readable_code
 *
 *  Return ptr to string representing a human readable
 *  error code from the ustcomm_return_code enum.
 */
const char *ustcomm_get_readable_code(int code)
{
	if (code == USTCOMM_OK) {
		return "Success";
	}
	if (code >= USTCOMM_ERR && code < USTCOMM_NR) {
		return ustcomm_readable_code[USTCOMM_ERR_INDEX(code)];
	}
	return strerror(code);
}

/*
 * 	ustcomm_connect_unix_sock
 *
 * 	Connect to unix socket using the path name.
 */
int ustcomm_connect_unix_sock(const char *pathname)
{
	struct sockaddr_un sun;
	int fd;
	int ret;

	/*
	 * libust threads require the close-on-exec flag for all
	 * resources so it does not leak file descriptors upon exec.
	 */
	fd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		perror("socket");
		ret = fd;
		goto error;
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
		goto error_connect;
	}

	return fd;

error_connect:
	close(fd);
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
		goto error;
	}

	return new_fd;

error:
	return -1;
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
	int fd;
	int ret = -1;

	/* Create server socket */
	if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
		perror("socket");
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
		goto error;
	}

	return fd;

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
	ssize_t ret = -1;

	memset(&msg, 0, sizeof(msg));

	iov[0].iov_base = buf;
	iov[0].iov_len = len;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	do {
		ret = recvmsg(sock, &msg, 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0 && errno != EPIPE) {
		perror("recvmsg");
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
	ssize_t ret = -1;

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
	ret = sendmsg(sock, &msg, MSG_NOSIGNAL);
	if (ret < 0 && errno != EPIPE) {
		perror("sendmsg");
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
	 * Note: the consumerd receiver only supports receiving one FD per
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

	ret = sendmsg(sock, &msg, 0);
	if (ret < 0 && errno != EPIPE) {
		perror("sendmsg");
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
	case -1:
		if (errno == ECONNRESET) {
			fprintf(stderr, "remote end closed connection\n");
			return 0;
		}
		return -1;
	default:
		fprintf(stderr, "incorrect message size: %zd\n", len);
		return -1;
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
		if (lur->ret_code != USTCOMM_OK) {
			/*
			 * Some errors are normal.. we should put this
			 * in a debug level message...
			 * fprintf(stderr, "remote operation failed with code %d.\n",
			 *	lur->ret_code);
			 */
			return lur->ret_code;
		}
		return 0;
	case -1:
		if (errno == ECONNRESET) {
			fprintf(stderr, "remote end closed connection\n");
			return -EINVAL;
		}
		return -1;
	default:
		fprintf(stderr, "incorrect message size: %zd\n", len);
		return len > 0 ? -1 : len;
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
	if (ret)
		return ret;
	return 0;
}


/*
 * Receives a single fd from socket.
 *
 * Returns the size of received data
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
		goto end;
	}
	if (ret != sizeof(data_fd)) {
		fprintf(stderr, "Received %d bytes, expected %zd", ret, sizeof(data_fd));
		goto end;
	}
	cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg) {
		fprintf(stderr, "Invalid control message header\n");
		ret = -1;
		goto end;
	}
	if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
		fprintf(stderr, "Didn't received any fd\n");
		ret = -1;
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
	return ret;
}
