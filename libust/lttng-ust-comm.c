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
static char global_apps_sock_path[PATH_MAX] = DEFAULT_GLOBAL_APPS_UNIX_SOCK;
static pthread_t global_ust_listener;

/* TODO: allow global_apps_sock_path override */

static char local_apps_sock_path[PATH_MAX];
static pthread_t local_ust_listener;

static
int setup_local_apps_socket(void)
{
	const char *home_dir;

	home_dir = (const char *) getenv("HOME");
	if (!home_dir)
		return -ENOENT;
	snprintf(local_apps_sock_path, PATH_MAX,
		 DEFAULT_HOME_APPS_UNIX_SOCK, home_dir);
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
int handle_message(int sock, struct lttcomm_ust_msg *lum)
{
	ssize_t len;
	int ret;

	switch (lum->cmd_type) {
	case LTTNG_UST_CREATE_SESSION:
	{
		struct lttcomm_ust_reply lur;

		DBG("Handling create session message");
		memset(&lur, 0, sizeof(lur));
		lur.cmd_type = LTTNG_UST_CREATE_SESSION;

		/* ... */
		ret = 0;

		if (!ret)
			lur.ret_code = LTTCOMM_OK;
		else
			lur.ret_code = LTTCOMM_SESSION_FAIL;
		lur.ret_val = 42;
		len = lttcomm_send_unix_sock(sock, &lur, sizeof(lur));
		switch (len) {
		case sizeof(lur):
			printf("message successfully sent\n");
			break;
		case -1:
			if (errno == ECONNRESET) {
				printf("remote end closed connection\n");
				return 0;
			}
			return -1;
		default:
			printf("incorrect message size: %zd\n", len);
			return -1;
		}
		break;
	}
	default:
		ERR("Unimplemented command %d", (int) lum->cmd_type);
		return -1;
	}
	return 0;
}

static
void *ust_listener_thread(void *arg)
{
	const char *sock_path = (const char *) arg;
	int sock;
	int ret;

	/* Restart trying to connect to the session daemon */
restart:

	/* Check for sessiond availability with pipe TODO */

	/* Register */
	ret = lttcomm_connect_unix_sock(sock_path);
	if (ret < 0) {
		ERR("Error connecting to global apps socket");
	}
	sock = ret;
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
			if (ret) {
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
	ret = close(sock);
	if (ret) {
		ERR("Error closing local apps socket");
	}
	goto restart;	/* try to reconnect */
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

	/* Connect to the per-user (local) sessiond apps socket */
	ret = setup_local_apps_socket();
	if (ret) {
		ERR("Error setting up to local apps socket");
	}
#if 0
	ret = pthread_create(&global_ust_listener, NULL,
			ust_listener_thread, global_apps_sock_path);
#endif //0
	ret = pthread_create(&local_ust_listener, NULL,
			ust_listener_thread, local_apps_sock_path);
}

void __attribute__((destructor)) lttng_ust_comm_exit(void)
{
	int ret;

	/*
	 * Using pthread_cancel here because:
	 * A) we don't want to hang application teardown.
	 * B) the thread is not allocating any resource.
	 */
	ret = pthread_cancel(global_ust_listener);
	if (ret) {
		ERR("Error cancelling global ust listener thread");
	}
	ret = pthread_cancel(local_ust_listener);
	if (ret) {
		ERR("Error cancelling local ust listener thread");
	}
}
