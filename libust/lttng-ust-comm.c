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
#include <sys/prctl.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <time.h>
#include <assert.h>
#include <signal.h>
#include <urcu/uatomic.h>

#include <lttng-ust-comm.h>
#include <ust/usterr-signal-safe.h>
#include <ust/lttng-ust-abi.h>
#include <ust/tracepoint.h>
#include <ust/tracepoint-internal.h>
#include <ust/ust.h>

/*
 * Has lttng ust comm constructor been called ?
 */
static int initialized;

/*
 * The ust_lock/ust_unlock lock is used as a communication thread mutex.
 * Held when handling a command, also held by fork() to deal with
 * removal of threads, and by exit path.
 */

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
 * Doing this for both the global and local sessiond.
 */
static int sem_count = { 2 };

/*
 * Info about socket and associated listener thread.
 */
struct sock_info {
	const char *name;
	char sock_path[PATH_MAX];
	int socket;
	pthread_t ust_listener;	/* listener thread */
	int root_handle;
	int constructor_sem_posted;
	int allowed;
};

/* Socket from app (connect) to session daemon (listen) for communication */
struct sock_info global_apps = {
	.name = "global",
	.sock_path = DEFAULT_GLOBAL_APPS_UNIX_SOCK,
	.socket = -1,
	.root_handle = -1,
	.allowed = 1,
};

/* TODO: allow global_apps_sock_path override */

struct sock_info local_apps = {
	.name = "local",
	.socket = -1,
	.root_handle = -1,
	.allowed = 0,	/* Check setuid bit first */
};

extern void ltt_ring_buffer_client_overwrite_init(void);
extern void ltt_ring_buffer_client_discard_init(void);
extern void ltt_ring_buffer_metadata_client_init(void);
extern void ltt_ring_buffer_client_overwrite_exit(void);
extern void ltt_ring_buffer_client_discard_exit(void);
extern void ltt_ring_buffer_metadata_client_exit(void);

static
int setup_local_apps(void)
{
	const char *home_dir;

	/*
	 * Disallow per-user tracing for setuid binaries.
	 */
	if (getuid() != geteuid()) {
		local_apps.allowed = 0;
		return 0;
	} else {
		local_apps.allowed = 1;
	}
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
	int prctl_ret;
	struct {
		uint32_t major;
		uint32_t minor;
		pid_t pid;
		pid_t ppid;
		uid_t uid;
		gid_t gid;
		char name[16];	/* process name */
	} reg_msg;

	reg_msg.major = LTTNG_UST_COMM_VERSION_MAJOR;
	reg_msg.minor = LTTNG_UST_COMM_VERSION_MINOR;
	reg_msg.pid = getpid();
	reg_msg.ppid = getppid();
	reg_msg.uid = getuid();
	reg_msg.gid = getgid();
	prctl_ret = prctl(PR_GET_NAME, (unsigned long) reg_msg.name, 0, 0, 0);
	if (prctl_ret) {
		ERR("Error executing prctl");
		return -errno;
	}

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
int handle_register_done(struct sock_info *sock_info)
{
	int ret;

	if (sock_info->constructor_sem_posted)
		return 0;
	sock_info->constructor_sem_posted = 1;
	ret = uatomic_add_return(&sem_count, -1);
	if (ret == 0) {
		ret = sem_post(&constructor_wait);
		assert(!ret);
	}
	return 0;
}

static
int handle_message(struct sock_info *sock_info,
		int sock, struct lttcomm_ust_msg *lum)
{
	int ret = 0;
	const struct objd_ops *ops;
	struct lttcomm_ust_reply lur;

	ust_lock();

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
			ret = handle_register_done(sock_info);
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

	ust_unlock();
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
	ust_lock();

	if (lttng_ust_comm_should_quit) {
		ust_unlock();
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
		ret = handle_register_done(sock_info);
		assert(!ret);
		ust_unlock();
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
			ust_unlock();
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
		ret = handle_register_done(sock_info);
		assert(!ret);
		ust_unlock();
		sleep(5);
		goto restart;
	}
	ust_unlock();

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

/*
 * Return values: -1: don't wait. 0: wait forever. 1: timeout wait.
 */
static
int get_timeout(struct timespec *constructor_timeout)
{
	long constructor_delay_ms = LTTNG_UST_DEFAULT_CONSTRUCTOR_TIMEOUT_MS;
	char *str_delay;
	int ret;

	str_delay = getenv("UST_REGISTER_TIMEOUT");
	if (str_delay) {
		constructor_delay_ms = strtol(str_delay, NULL, 10);
	}

	switch (constructor_delay_ms) {
	case -1:/* fall-through */
	case 0:
		return constructor_delay_ms;
	default:
		break;
	}

	/*
	 * If we are unable to find the current time, don't wait.
	 */
	ret = clock_gettime(CLOCK_REALTIME, constructor_timeout);
	if (ret) {
		return -1;
	}
	constructor_timeout->tv_sec += constructor_delay_ms / 1000UL;
	constructor_timeout->tv_nsec +=
		(constructor_delay_ms % 1000UL) * 1000000UL;
	if (constructor_timeout->tv_nsec >= 1000000000UL) {
		constructor_timeout->tv_sec++;
		constructor_timeout->tv_nsec -= 1000000000UL;
	}
	return 1;
}

/*
 * sessiond monitoring thread: monitor presence of global and per-user
 * sessiond by polling the application common named pipe.
 */
/* TODO */

void __attribute__((constructor)) lttng_ust_init(void)
{
	struct timespec constructor_timeout;
	int timeout_mode;
	int ret;

	if (uatomic_xchg(&initialized, 1) == 1)
		return;

	/*
	 * We want precise control over the order in which we construct
	 * our sub-libraries vs starting to receive commands from
	 * sessiond (otherwise leading to errors when trying to create
	 * sessiond before the init functions are completed).
	 */
	init_usterr();
	init_tracepoint();
	ltt_ring_buffer_metadata_client_init();
	ltt_ring_buffer_client_overwrite_init();
	ltt_ring_buffer_client_discard_init();

	timeout_mode = get_timeout(&constructor_timeout);

	ret = sem_init(&constructor_wait, 0, 0);
	assert(!ret);

	ret = setup_local_apps();
	if (ret) {
		ERR("Error setting up to local apps");
	}
	ret = pthread_create(&local_apps.ust_listener, NULL,
			ust_listener_thread, &local_apps);

	if (local_apps.allowed) {
		ret = pthread_create(&global_apps.ust_listener, NULL,
				ust_listener_thread, &global_apps);
	} else {
		handle_register_done(&local_apps);
	}

	switch (timeout_mode) {
	case 1:	/* timeout wait */
		do {
			ret = sem_timedwait(&constructor_wait,
					&constructor_timeout);
		} while (ret < 0 && errno == EINTR);
		if (ret < 0 && errno == ETIMEDOUT) {
			ERR("Timed out waiting for ltt-sessiond");
		} else {
			assert(!ret);
		}
		break;
	case -1:/* wait forever */
		do {
			ret = sem_wait(&constructor_wait);
		} while (ret < 0 && errno == EINTR);
		assert(!ret);
		break;
	case 0:	/* no timeout */
		break;
	}
}

static
void lttng_ust_cleanup(int exiting)
{
	cleanup_sock_info(&global_apps);
	if (local_apps.allowed) {
		cleanup_sock_info(&local_apps);
	}
	lttng_ust_abi_exit();
	ltt_events_exit();
	ltt_ring_buffer_client_discard_exit();
	ltt_ring_buffer_client_overwrite_exit();
	ltt_ring_buffer_metadata_client_exit();
	exit_tracepoint();
	if (!exiting) {
		/* Reinitialize values for fork */
		sem_count = 2;
		lttng_ust_comm_should_quit = 0;
		initialized = 0;
	}
}

void __attribute__((destructor)) lttng_ust_exit(void)
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
	ust_lock();
	lttng_ust_comm_should_quit = 1;
	ust_unlock();

	ret = pthread_cancel(global_apps.ust_listener);
	if (ret) {
		ERR("Error cancelling global ust listener thread");
	}
	if (local_apps.allowed) {
		ret = pthread_cancel(local_apps.ust_listener);
		if (ret) {
			ERR("Error cancelling local ust listener thread");
		}
	}
	lttng_ust_cleanup(1);
}

/*
 * We exclude the worker threads across fork and clone (except
 * CLONE_VM), because these system calls only keep the forking thread
 * running in the child.  Therefore, we don't want to call fork or clone
 * in the middle of an tracepoint or ust tracing state modification.
 * Holding this mutex protects these structures across fork and clone.
 */
void ust_before_fork(ust_fork_info_t *fork_info)
{
	/*
	 * Disable signals. This is to avoid that the child intervenes
	 * before it is properly setup for tracing. It is safer to
	 * disable all signals, because then we know we are not breaking
	 * anything by restoring the original mask.
         */
	sigset_t all_sigs;
	int ret;

	/* Disable signals */
	sigfillset(&all_sigs);
	ret = sigprocmask(SIG_BLOCK, &all_sigs, &fork_info->orig_sigs);
	if (ret == -1) {
		PERROR("sigprocmask");
	}
	ust_lock();
	rcu_bp_before_fork();
}

static void ust_after_fork_common(ust_fork_info_t *fork_info)
{
	int ret;

	DBG("process %d", getpid());
	ust_unlock();
	/* Restore signals */
	ret = sigprocmask(SIG_SETMASK, &fork_info->orig_sigs, NULL);
	if (ret == -1) {
		PERROR("sigprocmask");
	}
}

void ust_after_fork_parent(ust_fork_info_t *fork_info)
{
	DBG("process %d", getpid());
	rcu_bp_after_fork_parent();
	/* Release mutexes and reenable signals */
	ust_after_fork_common(fork_info);
}

/*
 * After fork, in the child, we need to cleanup all the leftover state,
 * except the worker thread which already magically disappeared thanks
 * to the weird Linux fork semantics. After tyding up, we call
 * lttng_ust_init() again to start over as a new PID.
 *
 * This is meant for forks() that have tracing in the child between the
 * fork and following exec call (if there is any).
 */
void ust_after_fork_child(ust_fork_info_t *fork_info)
{
	DBG("process %d", getpid());
	/* Release urcu mutexes */
	rcu_bp_after_fork_child();
	lttng_ust_cleanup(0);
	lttng_ust_init();
	/* Release mutexes and reenable signals */
	ust_after_fork_common(fork_info);
}
