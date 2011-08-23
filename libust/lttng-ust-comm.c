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
#include <semaphore.h>
#include <time.h>
#include <assert.h>

/*
 * communication thread mutex. Held when handling a command, also held
 * by fork() to deal with removal of threads, and by exit path.
 */
static pthread_mutex_t lttng_ust_comm_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Should the ust comm thread quit ? */
static int lttng_ust_comm_should_quit;

/*
 * Wait for either of these before continuing to the main
 * program:
 * - the register_done message from sessiond daemon
 *   (will let the sessiond daemon enable sessions before main
 *   starts.)
 * - sessiond daemon is not reachable.
 * - timeout (ensuring applications are resilient to session
 *   daemon problems).
 */
static sem_t constructor_wait;

/*
 * Info about socket and associated listener thread.
 */
struct sock_info {
	const char *name;
	char sock_path[PATH_MAX];
	int socket;
	pthread_t ust_listener;	/* listener thread */
	int root_handle;
};

/* Socket from app (connect) to session daemon (listen) for communication */
struct sock_info global_apps = {
	.name = "global",
	.sock_path = DEFAULT_GLOBAL_APPS_UNIX_SOCK,
	.socket = -1,
	.root_handle = -1,
};

/* TODO: allow global_apps_sock_path override */

struct sock_info local_apps = {
	.name = "local",
	.socket = -1,
	.root_handle = -1,
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
int send_reply(int sock, struct lttcomm_ust_reply *lur)
{
	ssize_t len;

	len = lttcomm_send_unix_sock(sock, lur, sizeof(*lur));
	switch (len) {
	case sizeof(*lur):
		DBG("message successfully sent");
		return 0;
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
}

static
int handle_register_done(void)
{
	int ret;

	ret = sem_post(&constructor_wait);
	assert(!ret);
	return 0;
}

static
int handle_message(struct sock_info *sock_info,
		int sock, struct lttcomm_ust_msg *lum)
{
	int ret = 0;
	const struct objd_ops *ops;
	struct lttcomm_ust_reply lur;

	pthread_mutex_lock(&lttng_ust_comm_mutex);

	memset(&lur, 0, sizeof(lur));

	if (lttng_ust_comm_should_quit) {
		ret = -EPERM;
		goto end;
	}

	ops = objd_ops(lum->handle);
	if (!ops) {
		ret = -ENOENT;
		goto end;
	}

	switch (lum->cmd) {
	case LTTNG_UST_REGISTER_DONE:
		if (lum->handle == LTTNG_UST_ROOT_HANDLE)
			ret = handle_register_done();
		else
			ret = -EINVAL;
		break;
	case LTTNG_UST_RELEASE:
		if (lum->handle == LTTNG_UST_ROOT_HANDLE)
			ret = -EPERM;
		else
			ret = objd_unref(lum->handle);
		break;
	default:
		if (ops->cmd)
			ret = ops->cmd(lum->handle, lum->cmd,
					(unsigned long) &lum->u);
		else
			ret = -ENOSYS;
		break;
	}

end:
	lur.handle = lum->handle;
	lur.cmd = lum->cmd;
	lur.ret_val = ret;
	if (ret >= 0) {
		lur.ret_code = LTTCOMM_OK;
	} else {
		lur.ret_code = LTTCOMM_SESSION_FAIL;
	}
	ret = send_reply(sock, &lur);

	pthread_mutex_unlock(&lttng_ust_comm_mutex);
	return ret;
}

static
void cleanup_sock_info(struct sock_info *sock_info)
{
	int ret;

	if (sock_info->socket != -1) {
		ret = close(sock_info->socket);
		if (ret) {
			ERR("Error closing local apps socket");
		}
		sock_info->socket = -1;
	}
	if (sock_info->root_handle != -1) {
		ret = objd_unref(sock_info->root_handle);
		if (ret) {
			ERR("Error unref root handle");
		}
		sock_info->root_handle = -1;
	}
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
			ERR("Error closing %s apps socket", sock_info->name);
		}
		sock_info->socket = -1;
	}

	/* Check for sessiond availability with pipe TODO */

	/* Register */
	ret = lttcomm_connect_unix_sock(sock_info->sock_path);
	if (ret < 0) {
		ERR("Error connecting to %s apps socket", sock_info->name);
		/*
		 * If we cannot find the sessiond daemon, don't delay
		 * constructor execution.
		 */
		ret = handle_register_done();
		assert(!ret);
		pthread_mutex_unlock(&lttng_ust_comm_mutex);
		sleep(5);
		goto restart;
	}

	sock_info->socket = sock = ret;

	/*
	 * Create only one root handle per listener thread for the whole
	 * process lifetime.
	 */
	if (sock_info->root_handle == -1) {
		ret = lttng_abi_create_root_handle();
		if (ret) {
			ERR("Error creating root handle");
			pthread_mutex_unlock(&lttng_ust_comm_mutex);
			goto quit;
		}
		sock_info->root_handle = ret;
	}

	ret = register_app_to_sessiond(sock);
	if (ret < 0) {
		ERR("Error registering to %s apps socket", sock_info->name);
		/*
		 * If we cannot register to the sessiond daemon, don't
		 * delay constructor execution.
		 */
		ret = handle_register_done();
		assert(!ret);
		pthread_mutex_unlock(&lttng_ust_comm_mutex);
		sleep(5);
		goto restart;
	}
	pthread_mutex_unlock(&lttng_ust_comm_mutex);

	for (;;) {
		ssize_t len;
		struct lttcomm_ust_msg lum;

		len = lttcomm_recv_unix_sock(sock, &lum, sizeof(lum));
		switch (len) {
		case 0:	/* orderly shutdown */
			DBG("%s ltt-sessiond has performed an orderly shutdown\n", sock_info->name);
			goto end;
		case sizeof(lum):
			DBG("message received\n");
			ret = handle_message(sock_info, sock, &lum);
			if (ret < 0) {
				ERR("Error handling message for %s socket", sock_info->name);
			}
			continue;
		case -1:
			if (errno == ECONNRESET) {
				ERR("%s remote end closed connection\n", sock_info->name);
				goto end;
			}
			goto end;
		default:
			ERR("incorrect message size (%s socket): %zd\n", sock_info->name, len);
			continue;
		}

	}
end:
	goto restart;	/* try to reconnect */
quit:
	return NULL;
}

static
int get_timeout(struct timespec *constructor_timeout)
{
	struct timespec constructor_delay =
		{
			.tv_sec = LTTNG_UST_DEFAULT_CONSTRUCTOR_TIMEOUT_S,
		  	.tv_nsec = LTTNG_UST_DEFAULT_CONSTRUCTOR_TIMEOUT_NS,
		};
	struct timespec realtime;
	int ret;

	ret = clock_gettime(CLOCK_REALTIME, &realtime);
	if (ret)
		return ret;

	constructor_timeout->tv_sec =
		realtime.tv_sec + constructor_delay.tv_sec;
	constructor_timeout->tv_nsec =
		constructor_delay.tv_nsec + realtime.tv_nsec;
	if (constructor_timeout->tv_nsec >= 1000000000UL) {
		constructor_timeout->tv_sec++;
		constructor_timeout->tv_nsec -= 1000000000UL;
	}
	return 0;
}

/*
 * sessiond monitoring thread: monitor presence of global and per-user
 * sessiond by polling the application common named pipe.
 */
/* TODO */

void __attribute__((constructor)) lttng_ust_comm_init(void)
{
	struct timespec constructor_timeout;
	int ret;

	init_usterr();

	ret = get_timeout(&constructor_timeout);
	assert(!ret);

	ret = sem_init(&constructor_wait, 0, 2);
	assert(!ret);

	ret = setup_local_apps_socket();
	if (ret) {
		ERR("Error setting up to local apps socket");
	}

	/*
	 * Wait for the pthread cond to let us continue to main program
	 * execution. Hold mutex across thread creation, so we start
	 * waiting for the condition before the threads can signal its
	 * completion.
	 */
	pthread_mutex_lock(&lttng_ust_comm_mutex);
	ret = pthread_create(&global_apps.ust_listener, NULL,
			ust_listener_thread, &global_apps);
	ret = pthread_create(&local_apps.ust_listener, NULL,
			ust_listener_thread, &local_apps);

	ret = sem_timedwait(&constructor_wait, &constructor_timeout);
	if (ret < 0 && errno == ETIMEDOUT) {
		ERR("Timed out waiting for ltt-sessiond");
	} else {
		assert(!ret);
	}
	pthread_mutex_unlock(&lttng_ust_comm_mutex);

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

	cleanup_sock_info(&global_apps);

	ret = pthread_cancel(local_apps.ust_listener);
	if (ret) {
		ERR("Error cancelling local ust listener thread");
	}

	cleanup_sock_info(&local_apps);

	lttng_ust_abi_exit();
	ltt_events_exit();
}
