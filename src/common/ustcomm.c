/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011 EfficiOS Inc.
 * Copyright (C) 2011-2013 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include <limits.h>
#include <stdint.h>
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
#include <inttypes.h>

#include <lttng/ust-ctl.h>
#include <lttng/ust-fd.h>
#include "common/ustcomm.h"
#include "common/macros.h"
#include "common/dynamic-type.h"
#include "common/logging.h"

#include "common/events.h"
#include "common/compat/pthread.h"

#define USTCOMM_MAX_SEND_FDS	4

static
ssize_t count_fields_recursive(size_t nr_fields,
		const struct lttng_ust_event_field * const *lttng_fields);
static
int serialize_one_field(struct lttng_ust_session *session,
		struct lttng_ust_ctl_field *fields, size_t *iter_output,
		const struct lttng_ust_event_field *lf,
		const char **prev_field_name);
static
int serialize_fields(struct lttng_ust_session *session,
		struct lttng_ust_ctl_field *lttng_ust_ctl_fields,
		size_t *iter_output, size_t nr_lttng_fields,
		const struct lttng_ust_event_field * const *lttng_fields);

/*
 * ustcomm_connect_unix_sock
 *
 * Connect to unix socket using the path name.
 *
 * Caller handles FD tracker.
 */
int ustcomm_connect_unix_sock(const char *pathname, long timeout)
{
	struct sockaddr_un sun;
	int fd, ret;

	/*
	 * libust threads require the close-on-exec flag for all
	 * resources so it does not leak file descriptors upon exec.
	 */
	fd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		PERROR("socket");
		ret = -errno;
		goto error;
	}
	if (timeout >= 0) {
		/* Give at least 10ms. */
		if (timeout < 10)
			timeout = 10;
		ret = ustcomm_setsockopt_snd_timeout(fd, timeout);
		if (ret < 0) {
			WARN("Error setting connect socket send timeout");
		}
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, pathname, sizeof(sun.sun_path));
	sun.sun_path[sizeof(sun.sun_path) - 1] = '\0';

	DBG("Connecting to '%s'", sun.sun_path);
	ret = connect(fd, (struct sockaddr *) &sun, sizeof(sun));
	if (ret < 0) {
		/*
		 * Don't print message on connect ENOENT error, because
		 * connect is used in normal execution to detect if
		 * sessiond is alive. ENOENT is when the unix socket
		 * file does not exist, and ECONNREFUSED is when the
		 * file exists but no sessiond is listening.
		 */
		if (errno != ECONNREFUSED && errno != ECONNRESET
				&& errno != ENOENT && errno != EACCES)
			PERROR("connect");
		ret = -errno;
		if (ret == -ECONNREFUSED || ret == -ECONNRESET)
			ret = -EPIPE;
		goto error_connect;
	}

	return fd;

error_connect:
	{
		int closeret;

		closeret = close(fd);
		if (closeret)
			PERROR("close");
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
		if (errno != ECONNABORTED)
			PERROR("accept");
		new_fd = -errno;
		if (new_fd == -ECONNABORTED)
			new_fd = -EPIPE;
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
		PERROR("socket");
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
		PERROR("bind");
		ret = -errno;
		goto error_close;
	}

	return fd;

error_close:
	{
		int closeret;

		closeret = close(fd);
		if (closeret) {
			PERROR("close");
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
		PERROR("listen");
	}

	return ret;
}

/*
 * ustcomm_close_unix_sock
 *
 * Close unix socket.
 *
 * Handles fd tracker internally.
 */
int ustcomm_close_unix_sock(int sock)
{
	int ret;

	lttng_ust_lock_fd_tracker();
	ret = close(sock);
	if (!ret) {
		lttng_ust_delete_fd_from_tracker(sock);
	} else {
		PERROR("close");
		ret = -errno;
	}
	lttng_ust_unlock_fd_tracker();

	return ret;
}

/*
 * ustcomm_shutdown_unix_sock
 *
 * Shutdown unix socket. Keeps the file descriptor open, but shutdown
 * communication.
 */
int ustcomm_shutdown_unix_sock(int sock)
{
	int ret;

	ret = shutdown(sock, SHUT_RDWR);
	if (ret) {
		PERROR("Socket shutdown error");
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
	ssize_t ret = -1;
	size_t len_last;

	memset(&msg, 0, sizeof(msg));

	iov[0].iov_base = buf;
	iov[0].iov_len = len;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	do {
		len_last = iov[0].iov_len;
		ret = recvmsg(sock, &msg, 0);
		if (ret > 0) {
			iov[0].iov_base += ret;
			iov[0].iov_len -= ret;
			assert(ret <= len_last);
		}
	} while ((ret > 0 && ret < len_last) || (ret < 0 && errno == EINTR));

	if (ret < 0) {
		if (errno != EPIPE && errno != ECONNRESET && errno != ECONNREFUSED)
			PERROR("recvmsg");
		ret = -errno;
		if (ret == -ECONNRESET || ret == -ECONNREFUSED)
			ret = -EPIPE;

		(void) ustcomm_shutdown_unix_sock(sock);
	} else if (ret > 0) {
		ret = len;
	}
	/* ret = 0 means an orderly shutdown. */

	return ret;
}

/*
 * ustcomm_send_unix_sock
 *
 * Send buf data of size len. Using sendmsg API.
 * Return the size of sent data.
 */
ssize_t ustcomm_send_unix_sock(int sock, const void *buf, size_t len)
{
	struct msghdr msg;
	struct iovec iov[1];
	ssize_t ret;

	memset(&msg, 0, sizeof(msg));

	iov[0].iov_base = (void *) buf;
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
		if (errno != EPIPE && errno != ECONNRESET)
			PERROR("sendmsg");
		ret = -errno;
		if (ret == -ECONNRESET)
			ret = -EPIPE;

		(void) ustcomm_shutdown_unix_sock(sock);
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
	if (!cmptr)
		return -EINVAL;
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
		ret = sendmsg(sock, &msg, MSG_NOSIGNAL);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		/*
		 * We consider EPIPE and ECONNRESET as expected.
		 */
		if (errno != EPIPE && errno != ECONNRESET) {
			PERROR("sendmsg");
		}
		ret = -errno;
		if (ret == -ECONNRESET)
			ret = -EPIPE;
	}
	return ret;
}

/*
 * Recv a message accompanied by fd(s) from a unix socket.
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
		ret = recvmsg(sock, &msg, MSG_CMSG_CLOEXEC);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		if (errno != EPIPE && errno != ECONNRESET) {
			PERROR("recvmsg fds");
		}
		ret = -errno;
		if (ret == -ECONNRESET)
			ret = -EPIPE;
		goto end;
	}
	if (ret == 0) {
		/* orderly shutdown */
		ret = -EPIPE;
		goto end;
	}
	if (ret != 1) {
		ERR("Error: Received %zd bytes, expected %d\n",
				ret, 1);
		goto end;
	}
	if (msg.msg_flags & MSG_CTRUNC) {
		ERR("Error: Control message truncated.\n");
		ret = -1;
		goto end;
	}
	cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg) {
		ERR("Error: Invalid control message header\n");
		ret = -1;
		goto end;
	}
	if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
		ERR("Didn't received any fd\n");
		ret = -1;
		goto end;
	}
	if (cmsg->cmsg_len != CMSG_LEN(sizeof_fds)) {
		ERR("Error: Received %zu bytes of ancillary data, expected %zu\n",
				(size_t) cmsg->cmsg_len, (size_t) CMSG_LEN(sizeof_fds));
		ret = -1;
		goto end;
	}

	memcpy(fds, CMSG_DATA(cmsg), sizeof_fds);

	ret = nb_fd;
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
			ERR("incorrect message size: %zd\n", len);
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
	{
		int err = 0;

		if (lur->handle != expected_handle) {
			ERR("Unexpected result message handle: "
				"expected: %u vs received: %u\n",
				expected_handle, lur->handle);
			err = 1;
		}
		if (lur->cmd != expected_cmd) {
			ERR("Unexpected result message command "
				"expected: %u vs received: %u\n",
				expected_cmd, lur->cmd);
			err = 1;
		}
		if (err) {
			return -EINVAL;
		} else {
			return lur->ret_code;
		}
	}
	default:
		if (len >= 0) {
			ERR("incorrect message size: %zd\n", len);
		}
		return len;
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
		void **_chan_data, uint64_t var_len,
		int *_wakeup_fd)
{
	void *chan_data;
	ssize_t len, nr_fd;
	int wakeup_fd, ret;

	if (var_len > LTTNG_UST_ABI_CHANNEL_DATA_MAX_LEN) {
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
	/* recv wakeup fd */
	lttng_ust_lock_fd_tracker();
	nr_fd = ustcomm_recv_fds_unix_sock(sock, &wakeup_fd, 1);
	if (nr_fd <= 0) {
		lttng_ust_unlock_fd_tracker();
		if (nr_fd < 0) {
			len = nr_fd;
			goto error_recv;
		} else {
			len = -EIO;
			goto error_recv;
		}
	}

	ret = lttng_ust_add_fd_to_tracker(wakeup_fd);
	if (ret < 0) {
		ret = close(wakeup_fd);
		if (ret) {
			PERROR("close on wakeup_fd");
		}
		len = -EIO;
		lttng_ust_unlock_fd_tracker();
		goto error_recv;
	}

	*_wakeup_fd = ret;
	lttng_ust_unlock_fd_tracker();

	*_chan_data = chan_data;
	return len;

error_recv:
	free(chan_data);
error_alloc:
error_check:
	return len;
}

ssize_t ustcomm_recv_event_notifier_notif_fd_from_sessiond(int sock,
		int *_event_notifier_notif_fd)
{
	ssize_t nr_fd;
	int event_notifier_notif_fd, ret;

	/* Receive event_notifier notification fd */
	lttng_ust_lock_fd_tracker();
	nr_fd = ustcomm_recv_fds_unix_sock(sock, &event_notifier_notif_fd, 1);
	if (nr_fd <= 0) {
		lttng_ust_unlock_fd_tracker();
		if (nr_fd < 0) {
			ret = nr_fd;
			goto error;
		} else {
			ret = -EIO;
			goto error;
		}
	}

	ret = lttng_ust_add_fd_to_tracker(event_notifier_notif_fd);
	if (ret < 0) {
		ret = close(event_notifier_notif_fd);
		if (ret) {
			PERROR("close on event_notifier notif fd");
		}
		ret = -EIO;
		lttng_ust_unlock_fd_tracker();
		goto error;
	}

	*_event_notifier_notif_fd = ret;
	lttng_ust_unlock_fd_tracker();

	ret = nr_fd;

error:
	return ret;
}

int ustcomm_recv_stream_from_sessiond(int sock,
		uint64_t *memory_map_size __attribute__((unused)),
		int *shm_fd, int *wakeup_fd)
{
	ssize_t len;
	int ret;
	int fds[2];

	/* recv shm fd and wakeup fd */
	lttng_ust_lock_fd_tracker();
	len = ustcomm_recv_fds_unix_sock(sock, fds, 2);
	if (len <= 0) {
		lttng_ust_unlock_fd_tracker();
		if (len < 0) {
			ret = len;
			goto error;
		} else {
			ret = -EIO;
			goto error;
		}
	}

	ret = lttng_ust_add_fd_to_tracker(fds[0]);
	if (ret < 0) {
		ret = close(fds[0]);
		if (ret) {
			PERROR("close on received shm_fd");
		}
		ret = -EIO;
		lttng_ust_unlock_fd_tracker();
		goto error;
	}
	*shm_fd = ret;

	ret = lttng_ust_add_fd_to_tracker(fds[1]);
	if (ret < 0) {
		ret = close(*shm_fd);
		if (ret) {
			PERROR("close on shm_fd");
		}
		*shm_fd = -1;
		ret = close(fds[1]);
		if (ret) {
			PERROR("close on received wakeup_fd");
		}
		ret = -EIO;
		lttng_ust_unlock_fd_tracker();
		goto error;
	}
	*wakeup_fd = ret;
	lttng_ust_unlock_fd_tracker();
	return 0;

error:
	return ret;
}

ssize_t ustcomm_recv_var_len_cmd_from_sessiond(int sock,
		void **_data, uint32_t var_len)
{
	void *data;
	ssize_t len;

	if (var_len > LTTNG_UST_ABI_CMD_MAX_LEN) {
		len = -EINVAL;
		goto error_check;
	}
	/* Receive variable length data */
	data = zmalloc(var_len);
	if (!data) {
		len = -ENOMEM;
		goto error_alloc;
	}
	len = ustcomm_recv_unix_sock(sock, data, var_len);
	if (len != var_len) {
		goto error_recv;
	}
	*_data = data;
	return len;

error_recv:
	free(data);
error_alloc:
error_check:
	return len;
}

int ustcomm_recv_counter_shm_from_sessiond(int sock,
		int *shm_fd)
{
	ssize_t len;
	int ret;
	int fds[1];

	/* recv shm fd fd */
	lttng_ust_lock_fd_tracker();
	len = ustcomm_recv_fds_unix_sock(sock, fds, 1);
	if (len <= 0) {
		lttng_ust_unlock_fd_tracker();
		if (len < 0) {
			ret = len;
			goto error;
		} else {
			ret = -EIO;
			goto error;
		}
	}

	ret = lttng_ust_add_fd_to_tracker(fds[0]);
	if (ret < 0) {
		ret = close(fds[0]);
		if (ret) {
			PERROR("close on received shm_fd");
		}
		ret = -EIO;
		lttng_ust_unlock_fd_tracker();
		goto error;
	}
	*shm_fd = ret;
	lttng_ust_unlock_fd_tracker();
	return 0;

error:
	return ret;
}

/*
 * Returns 0 on success, negative error value on error.
 */
int ustcomm_send_reg_msg(int sock,
		enum lttng_ust_ctl_socket_type type,
		uint32_t bits_per_long,
		uint32_t uint8_t_alignment,
		uint32_t uint16_t_alignment,
		uint32_t uint32_t_alignment,
		uint32_t uint64_t_alignment,
		uint32_t long_alignment,
		const char *procname)
{
	ssize_t len;
	struct lttng_ust_ctl_reg_msg reg_msg;

	reg_msg.magic = LTTNG_UST_ABI_COMM_MAGIC;
	reg_msg.major = LTTNG_UST_ABI_MAJOR_VERSION;
	reg_msg.minor = LTTNG_UST_ABI_MINOR_VERSION;
	reg_msg.pid = getpid();
	reg_msg.ppid = getppid();
	reg_msg.uid = getuid();
	reg_msg.gid = getgid();
	reg_msg.bits_per_long = bits_per_long;
	reg_msg.uint8_t_alignment = uint8_t_alignment;
	reg_msg.uint16_t_alignment = uint16_t_alignment;
	reg_msg.uint32_t_alignment = uint32_t_alignment;
	reg_msg.uint64_t_alignment = uint64_t_alignment;
	reg_msg.long_alignment = long_alignment;
	reg_msg.socket_type = type;
	memset(reg_msg.name, 0, sizeof(reg_msg.name));
	strncpy(reg_msg.name, procname, sizeof(reg_msg.name) - 1);
	memset(reg_msg.padding, 0, sizeof(reg_msg.padding));

	len = ustcomm_send_unix_sock(sock, &reg_msg, sizeof(reg_msg));
	if (len > 0 && len != sizeof(reg_msg))
		return -EIO;
	if (len < 0)
		return len;
	return 0;
}

static
ssize_t count_one_type(const struct lttng_ust_type_common *lt)
{
	switch (lt->type) {
	case lttng_ust_type_integer:
	case lttng_ust_type_float:
	case lttng_ust_type_string:
		return 1;
	case lttng_ust_type_enum:
		return count_one_type(lttng_ust_get_type_enum(lt)->container_type) + 1;
	case lttng_ust_type_array:
		return count_one_type(lttng_ust_get_type_array(lt)->elem_type) + 1;
	case lttng_ust_type_sequence:
		return count_one_type(lttng_ust_get_type_sequence(lt)->elem_type) + 1;
	case lttng_ust_type_struct:
		return count_fields_recursive(lttng_ust_get_type_struct(lt)->nr_fields,
				lttng_ust_get_type_struct(lt)->fields) + 1;

	case lttng_ust_type_dynamic:
	{
		const struct lttng_ust_event_field * const *choices;
		size_t nr_choices;
		int ret;

		ret = lttng_ust_dynamic_type_choices(&nr_choices,
			&choices);
		if (ret)
			return ret;
		/*
		 * Two fields for enum, one field for variant, and
		 * one field per choice.
		 */
		return count_fields_recursive(nr_choices, choices) + 3;
	}

	default:
		return -EINVAL;
	}
	return 0;
}

static
ssize_t count_fields_recursive(size_t nr_fields,
		const struct lttng_ust_event_field * const *lttng_fields)
{
	int i;
	ssize_t ret, count = 0;

	for (i = 0; i < nr_fields; i++) {
		const struct lttng_ust_event_field *lf;

		lf = lttng_fields[i];
		/* skip 'nowrite' fields */
		if (lf->nowrite)
			continue;
		ret = count_one_type(lf->type);
		if (ret < 0)
			return ret;	/* error */
		count += ret;
	}
	return count;
}

static
ssize_t count_ctx_fields_recursive(size_t nr_fields,
		struct lttng_ust_ctx_field *lttng_fields)
{
	int i;
	ssize_t ret, count = 0;

	for (i = 0; i < nr_fields; i++) {
		const struct lttng_ust_event_field *lf;

		lf = lttng_fields[i].event_field;
		/* skip 'nowrite' fields */
		if (lf->nowrite)
			continue;
		ret = count_one_type(lf->type);
		if (ret < 0)
			return ret;	/* error */
		count += ret;
	}
	return count;
}

static
int serialize_string_encoding(int32_t *ue,
		enum lttng_ust_string_encoding le)
{
	switch (le) {
	case lttng_ust_string_encoding_none:
		*ue = lttng_ust_ctl_encode_none;
		break;
	case lttng_ust_string_encoding_UTF8:
		*ue = lttng_ust_ctl_encode_UTF8;
		break;
	case lttng_ust_string_encoding_ASCII:
		*ue = lttng_ust_ctl_encode_ASCII;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static
int serialize_integer_type(struct lttng_ust_ctl_integer_type *uit,
		const struct lttng_ust_type_integer *lit,
		enum lttng_ust_string_encoding lencoding)
{
	int32_t encoding;

	uit->size = lit->size;
	uit->signedness = lit->signedness;
	uit->reverse_byte_order = lit->reverse_byte_order;
	uit->base = lit->base;
	if (serialize_string_encoding(&encoding, lencoding))
		return -EINVAL;
	uit->encoding = encoding;
	uit->alignment = lit->alignment;
	return 0;
}

static
int serialize_dynamic_type(struct lttng_ust_session *session,
		struct lttng_ust_ctl_field *fields, size_t *iter_output,
		const char *field_name)
{
	const struct lttng_ust_event_field * const *choices;
	char tag_field_name[LTTNG_UST_ABI_SYM_NAME_LEN];
	const struct lttng_ust_type_common *tag_type;
	const struct lttng_ust_event_field *tag_field_generic;
	struct lttng_ust_event_field tag_field = {
		.name = tag_field_name,
		.nowrite = 0,
	};
	struct lttng_ust_ctl_field *uf;
	size_t nr_choices, i;
	int ret;

	tag_field_generic = lttng_ust_dynamic_type_tag_field();
	tag_type = tag_field_generic->type;

	/* Serialize enum field. */
	strncpy(tag_field_name, field_name, LTTNG_UST_ABI_SYM_NAME_LEN);
	tag_field_name[LTTNG_UST_ABI_SYM_NAME_LEN - 1] = '\0';
	strncat(tag_field_name,
		"_tag",
		LTTNG_UST_ABI_SYM_NAME_LEN - strlen(tag_field_name) - 1);
	tag_field.type = tag_type;
	ret = serialize_one_field(session, fields, iter_output,
		&tag_field, NULL);
	if (ret)
		return ret;

	/* Serialize variant field. */
	uf = &fields[*iter_output];
	ret = lttng_ust_dynamic_type_choices(&nr_choices, &choices);
	if (ret)
		return ret;

	strncpy(uf->name, field_name, LTTNG_UST_ABI_SYM_NAME_LEN);
	uf->name[LTTNG_UST_ABI_SYM_NAME_LEN - 1] = '\0';
	uf->type.atype = lttng_ust_ctl_atype_variant_nestable;
	uf->type.u.variant_nestable.nr_choices = nr_choices;
	strncpy(uf->type.u.variant_nestable.tag_name,
		tag_field_name,
		LTTNG_UST_ABI_SYM_NAME_LEN);
	uf->type.u.variant_nestable.tag_name[LTTNG_UST_ABI_SYM_NAME_LEN - 1] = '\0';
	uf->type.u.variant_nestable.alignment = 0;
	(*iter_output)++;

	/* Serialize choice fields after variant. */
	for (i = 0; i < nr_choices; i++) {
		ret = serialize_one_field(session, fields,
			iter_output, choices[i], NULL);
		if (ret)
			return ret;
	}
	return 0;
}

static
int serialize_one_type(struct lttng_ust_session *session,
		struct lttng_ust_ctl_field *fields, size_t *iter_output,
		const char *field_name, const struct lttng_ust_type_common *lt,
		enum lttng_ust_string_encoding parent_encoding,
		const char *prev_field_name)
{
	int ret;

	/*
	 * Serializing a type (rather than a field) generates a lttng_ust_ctl_field
	 * entry with 0-length name.
	 */

	switch (lt->type) {
	case lttng_ust_type_integer:
	{
		struct lttng_ust_ctl_field *uf = &fields[*iter_output];
		struct lttng_ust_ctl_type *ut = &uf->type;

		if (field_name) {
			strncpy(uf->name, field_name, LTTNG_UST_ABI_SYM_NAME_LEN);
			uf->name[LTTNG_UST_ABI_SYM_NAME_LEN - 1] = '\0';
		} else {
			uf->name[0] = '\0';
		}
		ret = serialize_integer_type(&ut->u.integer, lttng_ust_get_type_integer(lt),
				parent_encoding);
		if (ret)
			return ret;
		ut->atype = lttng_ust_ctl_atype_integer;
		(*iter_output)++;
		break;
	}
	case lttng_ust_type_float:
	{
		struct lttng_ust_ctl_field *uf = &fields[*iter_output];
		struct lttng_ust_ctl_type *ut = &uf->type;
		struct lttng_ust_ctl_float_type *uft;
		const struct lttng_ust_type_float *lft;

		if (field_name) {
			strncpy(uf->name, field_name, LTTNG_UST_ABI_SYM_NAME_LEN);
			uf->name[LTTNG_UST_ABI_SYM_NAME_LEN - 1] = '\0';
		} else {
			uf->name[0] = '\0';
		}
		uft = &ut->u._float;
		lft = lttng_ust_get_type_float(lt);
		uft->exp_dig = lft->exp_dig;
		uft->mant_dig = lft->mant_dig;
		uft->alignment = lft->alignment;
		uft->reverse_byte_order = lft->reverse_byte_order;
		ut->atype = lttng_ust_ctl_atype_float;
		(*iter_output)++;
		break;
	}
	case lttng_ust_type_string:
	{
		struct lttng_ust_ctl_field *uf = &fields[*iter_output];
		struct lttng_ust_ctl_type *ut = &uf->type;
		int32_t encoding;

		if (field_name) {
			strncpy(uf->name, field_name, LTTNG_UST_ABI_SYM_NAME_LEN);
			uf->name[LTTNG_UST_ABI_SYM_NAME_LEN - 1] = '\0';
		} else {
			uf->name[0] = '\0';
		}
		ret = serialize_string_encoding(&encoding, lttng_ust_get_type_string(lt)->encoding);
		if (ret)
			return ret;
		ut->u.string.encoding = encoding;
		ut->atype = lttng_ust_ctl_atype_string;
		(*iter_output)++;
		break;
	}
	case lttng_ust_type_array:
	{
		struct lttng_ust_ctl_field *uf = &fields[*iter_output];
		struct lttng_ust_ctl_type *ut = &uf->type;

		if (field_name) {
			strncpy(uf->name, field_name, LTTNG_UST_ABI_SYM_NAME_LEN);
			uf->name[LTTNG_UST_ABI_SYM_NAME_LEN - 1] = '\0';
		} else {
			uf->name[0] = '\0';
		}
		ut->atype = lttng_ust_ctl_atype_array_nestable;
		ut->u.array_nestable.length = lttng_ust_get_type_array(lt)->length;
		ut->u.array_nestable.alignment = lttng_ust_get_type_array(lt)->alignment;
		(*iter_output)++;

		ret = serialize_one_type(session, fields, iter_output, NULL,
				lttng_ust_get_type_array(lt)->elem_type,
				lttng_ust_get_type_array(lt)->encoding, NULL);
		if (ret)
			return -EINVAL;
		break;
	}
	case lttng_ust_type_sequence:
	{
		struct lttng_ust_ctl_field *uf = &fields[*iter_output];
		struct lttng_ust_ctl_type *ut = &uf->type;
		const char *length_name = lttng_ust_get_type_sequence(lt)->length_name;

		if (field_name) {
			strncpy(uf->name, field_name, LTTNG_UST_ABI_SYM_NAME_LEN);
			uf->name[LTTNG_UST_ABI_SYM_NAME_LEN - 1] = '\0';
		} else {
			uf->name[0] = '\0';
		}
		ut->atype = lttng_ust_ctl_atype_sequence_nestable;
		/*
		 * If length_name field is NULL, use the previous field
		 * as length.
		 */
		if (!length_name)
			length_name = prev_field_name;
		if (!length_name)
			return -EINVAL;
		strncpy(ut->u.sequence_nestable.length_name,
			length_name, LTTNG_UST_ABI_SYM_NAME_LEN);
		ut->u.sequence_nestable.length_name[LTTNG_UST_ABI_SYM_NAME_LEN - 1] = '\0';
		ut->u.sequence_nestable.alignment = lttng_ust_get_type_sequence(lt)->alignment;
		(*iter_output)++;

		ret = serialize_one_type(session, fields, iter_output, NULL,
				lttng_ust_get_type_sequence(lt)->elem_type,
				lttng_ust_get_type_sequence(lt)->encoding, NULL);
		if (ret)
			return -EINVAL;
		break;
	}
	case lttng_ust_type_dynamic:
	{
		ret = serialize_dynamic_type(session, fields, iter_output,
				field_name);
		if (ret)
			return -EINVAL;
		break;
	}
	case lttng_ust_type_struct:
	{
		struct lttng_ust_ctl_field *uf = &fields[*iter_output];

		if (field_name) {
			strncpy(uf->name, field_name, LTTNG_UST_ABI_SYM_NAME_LEN);
			uf->name[LTTNG_UST_ABI_SYM_NAME_LEN - 1] = '\0';
		} else {
			uf->name[0] = '\0';
		}
		uf->type.atype = lttng_ust_ctl_atype_struct_nestable;
		uf->type.u.struct_nestable.nr_fields = lttng_ust_get_type_struct(lt)->nr_fields;
		uf->type.u.struct_nestable.alignment = lttng_ust_get_type_struct(lt)->alignment;
		(*iter_output)++;

		ret = serialize_fields(session, fields, iter_output,
				lttng_ust_get_type_struct(lt)->nr_fields,
				lttng_ust_get_type_struct(lt)->fields);
		if (ret)
			return -EINVAL;
		break;
	}
	case lttng_ust_type_enum:
	{
		struct lttng_ust_ctl_field *uf = &fields[*iter_output];
		struct lttng_ust_ctl_type *ut = &uf->type;

		if (field_name) {
			strncpy(uf->name, field_name, LTTNG_UST_ABI_SYM_NAME_LEN);
			uf->name[LTTNG_UST_ABI_SYM_NAME_LEN - 1] = '\0';
		} else {
			uf->name[0] = '\0';
		}
		strncpy(ut->u.enum_nestable.name, lttng_ust_get_type_enum(lt)->desc->name,
				LTTNG_UST_ABI_SYM_NAME_LEN);
		ut->u.enum_nestable.name[LTTNG_UST_ABI_SYM_NAME_LEN - 1] = '\0';
		ut->atype = lttng_ust_ctl_atype_enum_nestable;
		(*iter_output)++;

		ret = serialize_one_type(session, fields, iter_output, NULL,
				lttng_ust_get_type_enum(lt)->container_type,
				lttng_ust_string_encoding_none, NULL);
		if (ret)
			return -EINVAL;
		if (session) {
			const struct lttng_enum *_enum;

			_enum = lttng_ust_enum_get_from_desc(session, lttng_ust_get_type_enum(lt)->desc);
			if (!_enum)
				return -EINVAL;
			ut->u.enum_nestable.id = _enum->id;
		} else {
			ut->u.enum_nestable.id = -1ULL;
		}
		break;
	}
	default:
		return -EINVAL;
	}
	return 0;
}

static
int serialize_one_field(struct lttng_ust_session *session,
		struct lttng_ust_ctl_field *fields, size_t *iter_output,
		const struct lttng_ust_event_field *lf,
		const char **prev_field_name_p)
{
	const char *prev_field_name = NULL;
	int ret;

	/* skip 'nowrite' fields */
	if (lf->nowrite)
		return 0;

	if (prev_field_name_p)
		prev_field_name = *prev_field_name_p;
	ret = serialize_one_type(session, fields, iter_output, lf->name, lf->type,
			lttng_ust_string_encoding_none, prev_field_name);
	if (prev_field_name_p)
		*prev_field_name_p = lf->name;
	return ret;
}

static
int serialize_fields(struct lttng_ust_session *session,
		struct lttng_ust_ctl_field *lttng_ust_ctl_fields,
		size_t *iter_output, size_t nr_lttng_fields,
		const struct lttng_ust_event_field * const *lttng_fields)
{
	const char *prev_field_name = NULL;
	int ret;
	size_t i;

	for (i = 0; i < nr_lttng_fields; i++) {
		ret = serialize_one_field(session, lttng_ust_ctl_fields,
				iter_output, lttng_fields[i],
				&prev_field_name);
		if (ret)
			return ret;
	}
	return 0;
}

static
int alloc_serialize_fields(struct lttng_ust_session *session,
		size_t *_nr_write_fields,
		struct lttng_ust_ctl_field **lttng_ust_ctl_fields,
		size_t nr_fields,
		const struct lttng_ust_event_field * const *lttng_fields)
{
	struct lttng_ust_ctl_field *fields;
	int ret;
	size_t iter_output = 0;
	ssize_t nr_write_fields;

	nr_write_fields = count_fields_recursive(nr_fields, lttng_fields);
	if (nr_write_fields < 0) {
		return (int) nr_write_fields;
	}

	fields = zmalloc(nr_write_fields * sizeof(*fields));
	if (!fields)
		return -ENOMEM;

	ret = serialize_fields(session, fields, &iter_output, nr_fields,
			lttng_fields);
	if (ret)
		goto error_type;

	*_nr_write_fields = nr_write_fields;
	*lttng_ust_ctl_fields = fields;
	return 0;

error_type:
	free(fields);
	return ret;
}

static
int serialize_entries(struct lttng_ust_ctl_enum_entry **_entries,
		size_t nr_entries,
		const struct lttng_ust_enum_entry * const *lttng_entries)
{
	struct lttng_ust_ctl_enum_entry *entries;
	int i;

	/* Serialize the entries */
	entries = zmalloc(nr_entries * sizeof(*entries));
	if (!entries)
		return -ENOMEM;
	for (i = 0; i < nr_entries; i++) {
		struct lttng_ust_ctl_enum_entry *uentry;
		const struct lttng_ust_enum_entry *lentry;

		uentry = &entries[i];
		lentry = lttng_entries[i];

		uentry->start.value = lentry->start.value;
		uentry->start.signedness = lentry->start.signedness;
		uentry->end.value = lentry->end.value;
		uentry->end.signedness = lentry->end.signedness;
		strncpy(uentry->string, lentry->string, LTTNG_UST_ABI_SYM_NAME_LEN);
		uentry->string[LTTNG_UST_ABI_SYM_NAME_LEN - 1] = '\0';

		if (lentry->options & LTTNG_UST_ENUM_ENTRY_OPTION_IS_AUTO) {
			uentry->u.extra.options |=
				LTTNG_UST_CTL_UST_ENUM_ENTRY_OPTION_IS_AUTO;
		}
	}
	*_entries = entries;
	return 0;
}

static
int serialize_ctx_fields(struct lttng_ust_session *session,
		size_t *_nr_write_fields,
		struct lttng_ust_ctl_field **lttng_ust_ctl_fields,
		size_t nr_fields,
		struct lttng_ust_ctx_field *lttng_fields)
{
	struct lttng_ust_ctl_field *fields;
	const char *prev_field_name = NULL;
	size_t i, iter_output = 0;
	ssize_t nr_write_fields;
	int ret;

	nr_write_fields = count_ctx_fields_recursive(nr_fields,
			lttng_fields);
	if (nr_write_fields < 0) {
		return (int) nr_write_fields;
	}

	fields = zmalloc(nr_write_fields * sizeof(*fields));
	if (!fields)
		return -ENOMEM;

	for (i = 0; i < nr_fields; i++) {
		ret = serialize_one_field(session, fields, &iter_output,
				lttng_fields[i].event_field, &prev_field_name);
		if (ret)
			goto error_type;
	}

	*_nr_write_fields = nr_write_fields;
	*lttng_ust_ctl_fields = fields;
	return 0;

error_type:
	free(fields);
	return ret;
}

/*
 * Returns 0 on success, negative error value on error.
 */
int ustcomm_register_event(int sock,
	struct lttng_ust_session *session,
	int session_objd,		/* session descriptor */
	int channel_objd,		/* channel descriptor */
	const char *event_name,		/* event name (input) */
	int loglevel,
	const char *signature,		/* event signature (input) */
	size_t nr_fields,		/* fields */
	const struct lttng_ust_event_field * const *lttng_fields,
	const char *model_emf_uri,
	uint64_t user_token,
	uint32_t *id)			/* event id (output) */
{
	ssize_t len;
	struct {
		struct ustcomm_notify_hdr header;
		struct ustcomm_notify_event_msg m;
	} msg;
	struct {
		struct ustcomm_notify_hdr header;
		struct ustcomm_notify_event_reply r;
	} reply;
	size_t signature_len, fields_len, model_emf_uri_len;
	struct lttng_ust_ctl_field *fields = NULL;
	size_t nr_write_fields = 0;
	int ret;

	memset(&msg, 0, sizeof(msg));
	msg.header.notify_cmd = LTTNG_UST_CTL_NOTIFY_CMD_EVENT;
	msg.m.session_objd = session_objd;
	msg.m.channel_objd = channel_objd;
	strncpy(msg.m.event_name, event_name, LTTNG_UST_ABI_SYM_NAME_LEN);
	msg.m.event_name[LTTNG_UST_ABI_SYM_NAME_LEN - 1] = '\0';
	msg.m.loglevel = loglevel;
	msg.m.user_token = user_token;
	signature_len = strlen(signature) + 1;
	msg.m.signature_len = signature_len;

	/* Calculate fields len, serialize fields. */
	if (nr_fields > 0) {
		ret = alloc_serialize_fields(session, &nr_write_fields, &fields,
				nr_fields, lttng_fields);
		if (ret)
			return ret;
	}

	fields_len = sizeof(*fields) * nr_write_fields;
	msg.m.fields_len = fields_len;
	if (model_emf_uri) {
		model_emf_uri_len = strlen(model_emf_uri) + 1;
	} else {
		model_emf_uri_len = 0;
	}
	msg.m.model_emf_uri_len = model_emf_uri_len;

	len = ustcomm_send_unix_sock(sock, &msg, sizeof(msg));
	if (len > 0 && len != sizeof(msg)) {
		ret = -EIO;
		goto error_fields;
	}
	if (len < 0) {
		ret = len;
		goto error_fields;
	}

	/* send signature */
	len = ustcomm_send_unix_sock(sock, signature, signature_len);
	if (len > 0 && len != signature_len) {
		ret = -EIO;
		goto error_fields;
	}
	if (len < 0) {
		ret = len;
		goto error_fields;
	}

	/* send fields */
	if (fields_len > 0) {
		len = ustcomm_send_unix_sock(sock, fields, fields_len);
		if (len > 0 && len != fields_len) {
			ret = -EIO;
			goto error_fields;
		}
		if (len < 0) {
			ret = len;
			goto error_fields;
		}
	}
	free(fields);

	if (model_emf_uri_len) {
		/* send model_emf_uri */
		len = ustcomm_send_unix_sock(sock, model_emf_uri,
				model_emf_uri_len);
		if (len > 0 && len != model_emf_uri_len) {
			return -EIO;
		}
		if (len < 0) {
			return len;
		}
	}

	/* receive reply */
	len = ustcomm_recv_unix_sock(sock, &reply, sizeof(reply));
	switch (len) {
	case 0:	/* orderly shutdown */
		return -EPIPE;
	case sizeof(reply):
		if (reply.header.notify_cmd != msg.header.notify_cmd) {
			ERR("Unexpected result message command "
				"expected: %u vs received: %u\n",
				msg.header.notify_cmd, reply.header.notify_cmd);
			return -EINVAL;
		}
		if (reply.r.ret_code > 0)
			return -EINVAL;
		if (reply.r.ret_code < 0)
			return reply.r.ret_code;
		*id = reply.r.id;
		DBG("Sent register event notification for name \"%s\": ret_code %d, id %" PRIu32 "\n",
			event_name, reply.r.ret_code, reply.r.id);
		return 0;
	default:
		if (len < 0) {
			/* Transport level error */
			if (errno == EPIPE || errno == ECONNRESET)
				len = -errno;
			return len;
		} else {
			ERR("incorrect message size: %zd\n", len);
			return len;
		}
	}
	/* Unreached. */

	/* Error path only. */
error_fields:
	free(fields);
	return ret;
}

#ifdef CONFIG_LTTNG_UST_EXPERIMENTAL_COUNTER
/*
 * Returns 0 on success, negative error value on error.
 * Returns -EPIPE or -ECONNRESET if other end has hung up.
 */
int ustcomm_register_key(int sock,
	int session_objd,		/* session descriptor */
	int map_objd,			/* map descriptor */
	uint32_t dimension,
	const uint64_t *dimension_indexes,
	const char *key_string,		/* key string (input) */
	uint64_t user_token,
	uint64_t *index)		/* (output) */
{
	ssize_t len;
	struct {
		struct ustcomm_notify_hdr header;
		struct ustcomm_notify_key_msg m;
	} msg;
	struct {
		struct ustcomm_notify_hdr header;
		struct ustcomm_notify_key_reply r;
	} reply;
	size_t dimension_indexes_len;
	int ret;

	memset(&msg, 0, sizeof(msg));
	msg.header.notify_cmd = LTTNG_UST_CTL_NOTIFY_CMD_KEY;
	msg.m.session_objd = session_objd;
	msg.m.map_objd = map_objd;
	msg.m.dimension = dimension;
	dimension_indexes_len = sizeof(uint64_t) * dimension;
	msg.m.key_string_len = strlen(key_string) + 1;
	msg.m.user_token = user_token;

	len = ustcomm_send_unix_sock(sock, &msg, sizeof(msg));
	if (len > 0 && len != sizeof(msg)) {
		ret = -EIO;
		goto error_send;
	}
	if (len < 0) {
		ret = len;
		goto error_send;
	}

	/* send dimension_indexes */
	if (dimension_indexes) {
		len = ustcomm_send_unix_sock(sock, dimension_indexes, dimension_indexes_len);
		if (len > 0 && len != dimension_indexes_len) {
			ret = -EIO;
			goto error_dimension_indexes;
		}
		if (len < 0) {
			ret = len;
			goto error_dimension_indexes;
		}
	}

	/* send key_string */
	len = ustcomm_send_unix_sock(sock, key_string, msg.m.key_string_len);
	if (len > 0 && len != dimension_indexes_len) {
		ret = -EIO;
		goto error_dimension_indexes;
	}
	if (len < 0) {
		ret = len;
		goto error_dimension_indexes;
	}

	/* receive reply */
	len = ustcomm_recv_unix_sock(sock, &reply, sizeof(reply));
	switch (len) {
	case 0:	/* orderly shutdown */
		return -EPIPE;
	case sizeof(reply):
		if (reply.header.notify_cmd != msg.header.notify_cmd) {
			ERR("Unexpected result message command "
				"expected: %u vs received: %u\n",
				msg.header.notify_cmd, reply.header.notify_cmd);
			return -EINVAL;
		}
		if (reply.r.ret_code > 0)
			return -EINVAL;
		if (reply.r.ret_code < 0)
			return reply.r.ret_code;
		*index = reply.r.index;
		DBG("Sent register key notification for key \"%s\": ret_code %d, index %" PRIu64 "\n",
			key_string, reply.r.ret_code, reply.r.index);
		return 0;
	default:
		if (len < 0) {
			/* Transport level error */
			if (errno == EPIPE || errno == ECONNRESET)
				len = -errno;
			return len;
		} else {
			ERR("incorrect message size: %zd\n", len);
			return len;
		}
	}
	/* Unreached. */

	/* Error path only. */
error_dimension_indexes:
error_send:
	return ret;
}
#endif	/* CONFIG_LTTNG_UST_EXPERIMENTAL_COUNTER */

/*
 * Returns 0 on success, negative error value on error.
 * Returns -EPIPE or -ECONNRESET if other end has hung up.
 */
int ustcomm_register_enum(int sock,
	int session_objd,		/* session descriptor */
	const char *enum_name,		/* enum name (input) */
	size_t nr_entries,		/* entries */
	const struct lttng_ust_enum_entry * const *lttng_entries,
	uint64_t *id)
{
	ssize_t len;
	struct {
		struct ustcomm_notify_hdr header;
		struct ustcomm_notify_enum_msg m;
	} msg;
	struct {
		struct ustcomm_notify_hdr header;
		struct ustcomm_notify_enum_reply r;
	} reply;
	size_t entries_len;
	struct lttng_ust_ctl_enum_entry *entries = NULL;
	int ret;

	memset(&msg, 0, sizeof(msg));
	msg.header.notify_cmd = LTTNG_UST_CTL_NOTIFY_CMD_ENUM;
	msg.m.session_objd = session_objd;
	strncpy(msg.m.enum_name, enum_name, LTTNG_UST_ABI_SYM_NAME_LEN);
	msg.m.enum_name[LTTNG_UST_ABI_SYM_NAME_LEN - 1] = '\0';

	/* Calculate entries len, serialize entries. */
	if (nr_entries > 0) {
		ret = serialize_entries(&entries,
				nr_entries, lttng_entries);
		if (ret)
			return ret;
	}

	entries_len = sizeof(*entries) * nr_entries;
	msg.m.entries_len = entries_len;

	len = ustcomm_send_unix_sock(sock, &msg, sizeof(msg));
	if (len > 0 && len != sizeof(msg)) {
		ret = -EIO;
		goto error_entries;
	}
	if (len < 0) {
		ret = len;
		goto error_entries;
	}

	/* send entries */
	if (entries_len > 0) {
		len = ustcomm_send_unix_sock(sock, entries, entries_len);
		if (len > 0 && len != entries_len) {
			ret = -EIO;
			goto error_entries;
		}
		if (len < 0) {
			ret = len;
			goto error_entries;
		}
	}
	free(entries);
	entries = NULL;

	/* receive reply */
	len = ustcomm_recv_unix_sock(sock, &reply, sizeof(reply));
	switch (len) {
	case 0:	/* orderly shutdown */
		return -EPIPE;
	case sizeof(reply):
		if (reply.header.notify_cmd != msg.header.notify_cmd) {
			ERR("Unexpected result message command "
				"expected: %u vs received: %u\n",
				msg.header.notify_cmd, reply.header.notify_cmd);
			return -EINVAL;
		}
		if (reply.r.ret_code > 0)
			return -EINVAL;
		if (reply.r.ret_code < 0)
			return reply.r.ret_code;
		*id = reply.r.enum_id;
		DBG("Sent register enum notification for name \"%s\": ret_code %d\n",
			enum_name, reply.r.ret_code);
		return 0;
	default:
		if (len < 0) {
			/* Transport level error */
			if (errno == EPIPE || errno == ECONNRESET)
				len = -errno;
			return len;
		} else {
			ERR("incorrect message size: %zd\n", len);
			return len;
		}
	}
	return ret;

error_entries:
	free(entries);
	return ret;
}

/*
 * Returns 0 on success, negative error value on error.
 * Returns -EPIPE or -ECONNRESET if other end has hung up.
 */
int ustcomm_register_channel(int sock,
	struct lttng_ust_session *session,
	int session_objd,		/* session descriptor */
	int channel_objd,		/* channel descriptor */
	size_t nr_ctx_fields,
	struct lttng_ust_ctx_field *ctx_fields,
	uint32_t *chan_id,		/* channel id (output) */
	int *header_type) 		/* header type (output) */
{
	ssize_t len;
	struct {
		struct ustcomm_notify_hdr header;
		struct ustcomm_notify_channel_msg m;
	} msg;
	struct {
		struct ustcomm_notify_hdr header;
		struct ustcomm_notify_channel_reply r;
	} reply;
	size_t fields_len;
	struct lttng_ust_ctl_field *fields = NULL;
	int ret;
	size_t nr_write_fields = 0;

	memset(&msg, 0, sizeof(msg));
	msg.header.notify_cmd = LTTNG_UST_CTL_NOTIFY_CMD_CHANNEL;
	msg.m.session_objd = session_objd;
	msg.m.channel_objd = channel_objd;

	/* Calculate fields len, serialize fields. */
	if (nr_ctx_fields > 0) {
		ret = serialize_ctx_fields(session, &nr_write_fields, &fields,
				nr_ctx_fields, ctx_fields);
		if (ret)
			return ret;
	}

	fields_len = sizeof(*fields) * nr_write_fields;
	msg.m.ctx_fields_len = fields_len;
	len = ustcomm_send_unix_sock(sock, &msg, sizeof(msg));
	if (len > 0 && len != sizeof(msg)) {
		free(fields);
		return -EIO;
	}
	if (len < 0) {
		free(fields);
		return len;
	}

	/* send fields */
	if (fields_len > 0) {
		len = ustcomm_send_unix_sock(sock, fields, fields_len);
		free(fields);
		if (len > 0 && len != fields_len) {
			return -EIO;
		}
		if (len < 0) {
			return len;
		}
	} else {
		free(fields);
	}

	len = ustcomm_recv_unix_sock(sock, &reply, sizeof(reply));
	switch (len) {
	case 0:	/* orderly shutdown */
		return -EPIPE;
	case sizeof(reply):
		if (reply.header.notify_cmd != msg.header.notify_cmd) {
			ERR("Unexpected result message command "
				"expected: %u vs received: %u\n",
				msg.header.notify_cmd, reply.header.notify_cmd);
			return -EINVAL;
		}
		if (reply.r.ret_code > 0)
			return -EINVAL;
		if (reply.r.ret_code < 0)
			return reply.r.ret_code;
		*chan_id = reply.r.chan_id;
		switch (reply.r.header_type) {
		case 1:
		case 2:
			*header_type = reply.r.header_type;
			break;
		default:
			ERR("Unexpected channel header type %u\n",
				reply.r.header_type);
			return -EINVAL;
		}
		DBG("Sent register channel notification: chan_id %d, header_type %d\n",
			reply.r.chan_id, reply.r.header_type);
		return 0;
	default:
		if (len < 0) {
			/* Transport level error */
			if (errno == EPIPE || errno == ECONNRESET)
				len = -errno;
			return len;
		} else {
			ERR("incorrect message size: %zd\n", len);
			return len;
		}
	}
}

/*
 * Set socket receiving timeout.
 */
int ustcomm_setsockopt_rcv_timeout(int sock, unsigned int msec)
{
	int ret;
	struct timeval tv;

	tv.tv_sec = msec / 1000;
	tv.tv_usec = (msec * 1000 % 1000000);

	ret = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	if (ret < 0) {
		PERROR("setsockopt SO_RCVTIMEO");
		ret = -errno;
	}

	return ret;
}

/*
 * Set socket sending timeout.
 */
int ustcomm_setsockopt_snd_timeout(int sock, unsigned int msec)
{
	int ret;
	struct timeval tv;

	tv.tv_sec = msec / 1000;
	tv.tv_usec = (msec * 1000) % 1000000;

	ret = setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	if (ret < 0) {
		PERROR("setsockopt SO_SNDTIMEO");
		ret = -errno;
	}

	return ret;
}
