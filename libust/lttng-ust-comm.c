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
#include <lttng-sessiond-comm.h>
#include <ust/usterr-signal-safe.h>
#include <pthread.h>

/* Socket from app (connect) to session daemon (listen) for communication */
static int global_apps_socket = -1;
static char global_apps_sock_path[PATH_MAX] = DEFAULT_GLOBAL_APPS_UNIX_SOCK;
static pthread_t global_ust_listener;

/* TODO: allow global_apps_sock_path override */

static int local_apps_socket = -1;
static char local_apps_sock_path[PATH_MAX];
static pthread_t local_ust_listener;

static
int connect_global_apps_socket(void)
{
	int ret;

	ret = lttcomm_connect_unix_sock(global_apps_sock_path);
	if (ret < 0)
		return ret;
	global_apps_socket = ret;

	return 0;
}

static
int connect_local_apps_socket(void)
{
	const char *home_dir;
	int ret;

	home_dir = (const char *) getenv("HOME");
	if (!home_dir)
		return -ENOENT;
	snprintf(local_apps_sock_path, PATH_MAX,
		 DEFAULT_HOME_APPS_UNIX_SOCK, home_dir);

	ret = lttcomm_connect_unix_sock(local_apps_sock_path);
	if (ret < 0)
		return ret;
	local_apps_socket = ret;


	return 0;
}

static
int register_app_to_sessiond(int socket)
{
	ssize_t ret;
	struct {
		pid_t pid;
		uid_t uid;
	} reg_msg;

	reg_msg.pid = getpid();
	reg_msg.uid = getuid();

	ret = lttcomm_send_unix_sock(socket, &reg_msg, sizeof(reg_msg));
	if (ret >= 0 && ret != sizeof(reg_msg))
		return -EIO;
	return ret;
}


static
int parse_message(struct lttcomm_session_msg *lsm)
{
	switch (lsm->cmd_type) {
	case LTTNG_CREATE_SESSION:
		DBG("Handling create session message");


		break;
	default:
		ERR("Unimplemented command %d", (int) lsm->cmd_type);
		return -1;
	}
	return 0;
}

static
void *ust_listener_thread(void *arg)
{
	int sock = *(int *) arg;
	int ret;

	for (;;) {
		ssize_t len;
		struct lttcomm_session_msg lsm;

		/* Receive session handle */
		len = lttcomm_recv_unix_sock(sock, &lsm, sizeof(lsm));
		switch (len) {
		case 0:	/* orderly shutdown */
			DBG("ltt-sessiond has performed an orderly shutdown\n");
			goto end;
		case sizeof(lsm):
			DBG("message received\n");
			ret = parse_message(&lsm);
			if (ret) {
				ERR("Error parsing message\n");
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

#if 0
	/* Connect to the global sessiond apps socket */
	ret = connect_global_apps_socket();
	if (ret) {
		ERR("Error connecting to global apps socket");
	}
#endif //0

	/* Connect to the per-user (local) sessiond apps socket */
	ret = connect_local_apps_socket();
	if (ret) {
		ERR("Error connecting to local apps socket");
	}

	if (global_apps_socket >= 0) {
		ret = register_app_to_sessiond(global_apps_socket);
		if (ret < 0) {
			ERR("Error registering app to global apps socket");
		}
	}
	if (local_apps_socket >= 0) {
		ret = register_app_to_sessiond(local_apps_socket);
		if (ret < 0) {
			ERR("Error registering app to local apps socket");
		}
		ret = pthread_create(&local_ust_listener, NULL,
				ust_listener_thread, &local_apps_socket);
	}
}

void __attribute__((destructor)) lttng_ust_comm_exit(void)
{
	int ret;

#if 0
	ERR("dest %d", global_apps_socket);
	if (global_apps_socket >= 0) {
		ret = unregister_app_to_sessiond(global_apps_socket);
		if (ret < 0) {
			ERR("Error registering app to global apps socket");
		}
		ret = close(global_apps_socket);
		if (ret) {
			ERR("Error closing global apps socket");
		}
	}
#endif
	if (local_apps_socket >= 0) {
		/*
		 * Using pthread_cancel here because:
		 * A) we don't want to hang application teardown.
		 * B) the thread is not allocating any resource.
		 */
		ret = pthread_cancel(local_ust_listener);
		if (ret) {
			ERR("Error joining local ust listener thread");
		}

		ret = close(local_apps_socket);
		if (ret) {
			ERR("Error closing local apps socket");
		}
	}
}
