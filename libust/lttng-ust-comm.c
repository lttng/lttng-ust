/*
 * lttng-ust-comm.c
 *
 * Copyright (C) 2011 David Goulet <david.goulet@polymtl.ca>
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <ust/lttng-ust-abi.h>
#include <lttng-ust-comm.h>
#include <ust/usterr-signal-safe.h>
#include <pthread.h>
#include <assert.h>

/*
 * communication thread mutex. Held when handling a command, also held
 * by fork() to deal with removal of threads, and by exit path.
 */
static pthread_mutex_t lttng_ust_comm_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Should the ust comm thread quit ? */
static int lttng_ust_comm_should_quit;

/*
 * Info about socket and associated listener thread.
 */
struct sock_info {
	char sock_path[PATH_MAX];
	int socket;
	pthread_t ust_listener;	/* listener thread */
};

/* Socket from app (connect) to session daemon (listen) for communication */
struct sock_info global_apps = {
	.sock_path = DEFAULT_GLOBAL_APPS_UNIX_SOCK,
	.socket = -1,
};

/* TODO: allow global_apps_sock_path override */

struct sock_info local_apps = {
	.socket = -1,
};

static
int setup_local_apps_socket(void)
{
	const char *home_dir;

	home_dir = (const char *) getenv("HOME");
	if (!home_dir)
		return -ENOENT;
	snprintf(local_apps.sock_path, PATH_MAX,
		 DEFAULT_HOME_APPS_UNIX_SOCK, home_dir);
	return 0;
}

static
int register_app_to_sessiond(int socket)
{
	ssize_t ret;
	struct {
		uint32_t major;
		uint32_t minor;
		pid_t pid;
		uid_t uid;
	} reg_msg;

	reg_msg.major = LTTNG_UST_COMM_VERSION_MAJOR;
	reg_msg.minor = LTTNG_UST_COMM_VERSION_MINOR;
	reg_msg.pid = getpid();
	reg_msg.uid = getuid();

	ret = lttcomm_send_unix_sock(socket, &reg_msg, sizeof(reg_msg));
	if (ret >= 0 && ret != sizeof(reg_msg))
		return -EIO;
	return ret;
}

static
int handle_message(int sock, struct lttcomm_ust_msg *lum)
{
	ssize_t len;
	int ret = 0;

	pthread_mutex_lock(&lttng_ust_comm_mutex);

	if (lttng_ust_comm_should_quit) {
		ret = 0;
		goto end;
	}

	switch (lum->cmd_type) {
	case UST_CREATE_SESSION:
	{
		struct lttcomm_ust_reply lur;

		DBG("Handling create session message");
		memset(&lur, 0, sizeof(lur));
		lur.cmd_type = UST_CREATE_SESSION;

		ret = lttng_abi_create_session();
		if (ret >= 0) {
			lur.ret_val = ret;
			lur.ret_code = LTTCOMM_OK;
		} else {
			lur.ret_code = LTTCOMM_SESSION_FAIL;
		}
		len = lttcomm_send_unix_sock(sock, &lur, sizeof(lur));
		switch (len) {
		case sizeof(lur):
			DBG("message successfully sent");
			break;
		case -1:
			if (errno == ECONNRESET) {
				printf("remote end closed connection\n");
				ret = 0;
				goto end;
			}
			ret = -1;
			goto end;
		default:
			printf("incorrect message size: %zd\n", len);
			ret = -1;
			goto end;
		}
		break;
	}
	case UST_RELEASE:
	{
		struct lttcomm_ust_reply lur;

		DBG("Handling release message, handle: %d",
			lum->handle);
		memset(&lur, 0, sizeof(lur));
		lur.cmd_type = UST_RELEASE;

		ret = objd_unref(lum->handle);
		if (!ret) {
			lur.ret_code = LTTCOMM_OK;
		} else {
			lur.ret_code = LTTCOMM_ERR;
		}
		len = lttcomm_send_unix_sock(sock, &lur, sizeof(lur));
		switch (len) {
		case sizeof(lur):
			DBG("message successfully sent\n");
			break;
		case -1:
			if (errno == ECONNRESET) {
				printf("remote end closed connection\n");
				ret = 0;
				goto end;
			}
			ret = -1;
			goto end;
		default:
			printf("incorrect message size: %zd\n", len);
			ret = -1;
			goto end;
		}
		break;
	}
	default:
		ERR("Unimplemented command %d", (int) lum->cmd_type);
		ret = -1;
		goto end;
	}
end:
	pthread_mutex_unlock(&lttng_ust_comm_mutex);
	return ret;
}

/*
 * This thread does not allocate any resource, except within
 * handle_message, within mutex protection. This mutex protects against
 * fork and exit.
 * The other moment it allocates resources is at socket connexion, which
 * is also protected by the mutex.
 */
static
void *ust_listener_thread(void *arg)
{
	struct sock_info *sock_info = arg;
	int sock, ret;

	/* Restart trying to connect to the session daemon */
restart:
	pthread_mutex_lock(&lttng_ust_comm_mutex);

	if (lttng_ust_comm_should_quit) {
		pthread_mutex_unlock(&lttng_ust_comm_mutex);
		goto quit;
	}

	if (sock_info->socket != -1) {
		ret = close(sock_info->socket);
		if (ret) {
			ERR("Error closing local apps socket");
		}
		sock_info->socket = -1;
	}
	/* Check for sessiond availability with pipe TODO */

	/* Register */
	ret = lttcomm_connect_unix_sock(sock_info->sock_path);
	if (ret < 0) {
		ERR("Error connecting to global apps socket");
		pthread_mutex_unlock(&lttng_ust_comm_mutex);
		goto restart;
	} else {
		sock_info->socket = sock = ret;
		pthread_mutex_unlock(&lttng_ust_comm_mutex);
	}

	ret = register_app_to_sessiond(sock);
	if (ret < 0) {
		ERR("Error registering app to local apps socket");
		sleep(5);
		goto restart;
	}
	for (;;) {
		ssize_t len;
		struct lttcomm_ust_msg lum;

		/* Receive session handle */
		len = lttcomm_recv_unix_sock(sock, &lum, sizeof(lum));
		switch (len) {
		case 0:	/* orderly shutdown */
			DBG("ltt-sessiond has performed an orderly shutdown\n");
			goto end;
		case sizeof(lum):
			DBG("message received\n");
			ret = handle_message(sock, &lum);
			if (ret < 0) {
				ERR("Error handling message\n");
			}
			continue;
		case -1:
			if (errno == ECONNRESET) {
				ERR("remote end closed connection\n");
				goto end;
			}
			goto end;
		default:
			ERR("incorrect message size: %zd\n", len);
			continue;
		}

	}
end:
	goto restart;	/* try to reconnect */
quit:
	return NULL;
}


/*
 * sessiond monitoring thread: monitor presence of global and per-user
 * sessiond by polling the application common named pipe.
 */
/* TODO */

void __attribute__((constructor)) lttng_ust_comm_init(void)
{
	int ret;

	init_usterr();

	ret = setup_local_apps_socket();
	if (ret) {
		ERR("Error setting up to local apps socket");
	}
#if 0
	ret = pthread_create(&global_apps.ust_listener, NULL,
			ust_listener_thread, &global_apps);
#endif //0
	ret = pthread_create(&local_apps.ust_listener, NULL,
			ust_listener_thread, &local_apps);
}

void __attribute__((destructor)) lttng_ust_comm_exit(void)
{
	int ret;

	/*
	 * Using pthread_cancel here because:
	 * A) we don't want to hang application teardown.
	 * B) the thread is not allocating any resource.
	 */

	/*
	 * Require the communication thread to quit. Synchronize with
	 * mutexes to ensure it is not in a mutex critical section when
	 * pthread_cancel is later called.
	 */
	pthread_mutex_lock(&lttng_ust_comm_mutex);
	lttng_ust_comm_should_quit = 1;
	pthread_mutex_unlock(&lttng_ust_comm_mutex);

#if 0
	ret = pthread_cancel(global_apps.ust_listener);
	if (ret) {
		ERR("Error cancelling global ust listener thread");
	}
#endif //0
	if (global_apps.socket != -1) {
		ret = close(global_apps.socket);
		assert(!ret);
	}

	ret = pthread_cancel(local_apps.ust_listener);
	if (ret) {
		ERR("Error cancelling local ust listener thread");
	}

	if (local_apps.socket != -1) {
		ret = close(local_apps.socket);
		assert(!ret);
	}

	lttng_ust_abi_exit();
	ltt_events_exit();
}
