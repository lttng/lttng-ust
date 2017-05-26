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

#define _LGPL_SOURCE
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <time.h>
#include <assert.h>
#include <signal.h>
#include <limits.h>
#include <urcu/uatomic.h>
#include <urcu/futex.h>
#include <urcu/compiler.h>

#include <lttng/ust-events.h>
#include <lttng/ust-abi.h>
#include <lttng/ust.h>
#include <lttng/ust-error.h>
#include <lttng/ust-ctl.h>
#include <urcu/tls-compat.h>
#include <ust-comm.h>
#include <ust-fd.h>
#include <usterr-signal-safe.h>
#include <helper.h>
#include "tracepoint-internal.h"
#include "lttng-tracer-core.h"
#include "compat.h"
#include "../libringbuffer/rb-init.h"
#include "lttng-ust-statedump.h"
#include "clock.h"
#include "../libringbuffer/getcpu.h"
#include "getenv.h"

/*
 * Has lttng ust comm constructor been called ?
 */
static int initialized;

/*
 * The ust_lock/ust_unlock lock is used as a communication thread mutex.
 * Held when handling a command, also held by fork() to deal with
 * removal of threads, and by exit path.
 *
 * The UST lock is the centralized mutex across UST tracing control and
 * probe registration.
 *
 * ust_exit_mutex must never nest in ust_mutex.
 *
 * ust_fork_mutex must never nest in ust_mutex.
 *
 * ust_mutex_nest is a per-thread nesting counter, allowing the perf
 * counter lazy initialization called by events within the statedump,
 * which traces while the ust_mutex is held.
 *
 * ust_lock nests within the dynamic loader lock (within glibc) because
 * it is taken within the library constructor.
 */
static pthread_mutex_t ust_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Allow nesting the ust_mutex within the same thread. */
static DEFINE_URCU_TLS(int, ust_mutex_nest);

/*
 * ust_exit_mutex protects thread_active variable wrt thread exit. It
 * cannot be done by ust_mutex because pthread_cancel(), which takes an
 * internal libc lock, cannot nest within ust_mutex.
 *
 * It never nests within a ust_mutex.
 */
static pthread_mutex_t ust_exit_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * ust_fork_mutex protects base address statedump tracing against forks. It
 * prevents the dynamic loader lock to be taken (by base address statedump
 * tracing) while a fork is happening, thus preventing deadlock issues with
 * the dynamic loader lock.
 */
static pthread_mutex_t ust_fork_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Should the ust comm thread quit ? */
static int lttng_ust_comm_should_quit;

/*
 * This variable can be tested by applications to check whether
 * lttng-ust is loaded. They simply have to define their own
 * "lttng_ust_loaded" weak symbol, and test it. It is set to 1 by the
 * library constructor.
 */
int lttng_ust_loaded __attribute__((weak));

/*
 * Return 0 on success, -1 if should quit.
 * The lock is taken in both cases.
 * Signal-safe.
 */
int ust_lock(void)
{
	sigset_t sig_all_blocked, orig_mask;
	int ret, oldstate;

	ret = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);
	if (ret) {
		ERR("pthread_setcancelstate: %s", strerror(ret));
	}
	if (oldstate != PTHREAD_CANCEL_ENABLE) {
		ERR("pthread_setcancelstate: unexpected oldstate");
	}
	sigfillset(&sig_all_blocked);
	ret = pthread_sigmask(SIG_SETMASK, &sig_all_blocked, &orig_mask);
	if (ret) {
		ERR("pthread_sigmask: %s", strerror(ret));
	}
	if (!URCU_TLS(ust_mutex_nest)++)
		pthread_mutex_lock(&ust_mutex);
	ret = pthread_sigmask(SIG_SETMASK, &orig_mask, NULL);
	if (ret) {
		ERR("pthread_sigmask: %s", strerror(ret));
	}
	if (lttng_ust_comm_should_quit) {
		return -1;
	} else {
		return 0;
	}
}

/*
 * ust_lock_nocheck() can be used in constructors/destructors, because
 * they are already nested within the dynamic loader lock, and therefore
 * have exclusive access against execution of liblttng-ust destructor.
 * Signal-safe.
 */
void ust_lock_nocheck(void)
{
	sigset_t sig_all_blocked, orig_mask;
	int ret, oldstate;

	ret = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);
	if (ret) {
		ERR("pthread_setcancelstate: %s", strerror(ret));
	}
	if (oldstate != PTHREAD_CANCEL_ENABLE) {
		ERR("pthread_setcancelstate: unexpected oldstate");
	}
	sigfillset(&sig_all_blocked);
	ret = pthread_sigmask(SIG_SETMASK, &sig_all_blocked, &orig_mask);
	if (ret) {
		ERR("pthread_sigmask: %s", strerror(ret));
	}
	if (!URCU_TLS(ust_mutex_nest)++)
		pthread_mutex_lock(&ust_mutex);
	ret = pthread_sigmask(SIG_SETMASK, &orig_mask, NULL);
	if (ret) {
		ERR("pthread_sigmask: %s", strerror(ret));
	}
}

/*
 * Signal-safe.
 */
void ust_unlock(void)
{
	sigset_t sig_all_blocked, orig_mask;
	int ret, oldstate;

	sigfillset(&sig_all_blocked);
	ret = pthread_sigmask(SIG_SETMASK, &sig_all_blocked, &orig_mask);
	if (ret) {
		ERR("pthread_sigmask: %s", strerror(ret));
	}
	if (!--URCU_TLS(ust_mutex_nest))
		pthread_mutex_unlock(&ust_mutex);
	ret = pthread_sigmask(SIG_SETMASK, &orig_mask, NULL);
	if (ret) {
		ERR("pthread_sigmask: %s", strerror(ret));
	}
	ret = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
	if (ret) {
		ERR("pthread_setcancelstate: %s", strerror(ret));
	}
	if (oldstate != PTHREAD_CANCEL_DISABLE) {
		ERR("pthread_setcancelstate: unexpected oldstate");
	}
}

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
 * Counting nesting within lttng-ust. Used to ensure that calling fork()
 * from liblttng-ust does not execute the pre/post fork handlers.
 */
static DEFINE_URCU_TLS(int, lttng_ust_nest_count);

/*
 * Info about socket and associated listener thread.
 */
struct sock_info {
	const char *name;
	pthread_t ust_listener;	/* listener thread */
	int root_handle;
	int constructor_sem_posted;
	int allowed;
	int global;
	int thread_active;

	char sock_path[PATH_MAX];
	int socket;
	int notify_socket;

	char wait_shm_path[PATH_MAX];
	char *wait_shm_mmap;
	/* Keep track of lazy state dump not performed yet. */
	int statedump_pending;
};

/* Socket from app (connect) to session daemon (listen) for communication */
struct sock_info global_apps = {
	.name = "global",
	.global = 1,

	.root_handle = -1,
	.allowed = 1,
	.thread_active = 0,

	.sock_path = LTTNG_DEFAULT_RUNDIR "/" LTTNG_UST_SOCK_FILENAME,
	.socket = -1,
	.notify_socket = -1,

	.wait_shm_path = "/" LTTNG_UST_WAIT_FILENAME,

	.statedump_pending = 0,
};

/* TODO: allow global_apps_sock_path override */

struct sock_info local_apps = {
	.name = "local",
	.global = 0,
	.root_handle = -1,
	.allowed = 0,	/* Check setuid bit first */
	.thread_active = 0,

	.socket = -1,
	.notify_socket = -1,

	.statedump_pending = 0,
};

static int wait_poll_fallback;

static const char *cmd_name_mapping[] = {
	[ LTTNG_UST_RELEASE ] = "Release",
	[ LTTNG_UST_SESSION ] = "Create Session",
	[ LTTNG_UST_TRACER_VERSION ] = "Get Tracer Version",

	[ LTTNG_UST_TRACEPOINT_LIST ] = "Create Tracepoint List",
	[ LTTNG_UST_WAIT_QUIESCENT ] = "Wait for Quiescent State",
	[ LTTNG_UST_REGISTER_DONE ] = "Registration Done",
	[ LTTNG_UST_TRACEPOINT_FIELD_LIST ] = "Create Tracepoint Field List",

	/* Session FD commands */
	[ LTTNG_UST_CHANNEL ] = "Create Channel",
	[ LTTNG_UST_SESSION_START ] = "Start Session",
	[ LTTNG_UST_SESSION_STOP ] = "Stop Session",

	/* Channel FD commands */
	[ LTTNG_UST_STREAM ] = "Create Stream",
	[ LTTNG_UST_EVENT ] = "Create Event",

	/* Event and Channel FD commands */
	[ LTTNG_UST_CONTEXT ] = "Create Context",
	[ LTTNG_UST_FLUSH_BUFFER ] = "Flush Buffer",

	/* Event, Channel and Session commands */
	[ LTTNG_UST_ENABLE ] = "Enable",
	[ LTTNG_UST_DISABLE ] = "Disable",

	/* Tracepoint list commands */
	[ LTTNG_UST_TRACEPOINT_LIST_GET ] = "List Next Tracepoint",
	[ LTTNG_UST_TRACEPOINT_FIELD_LIST_GET ] = "List Next Tracepoint Field",

	/* Event FD commands */
	[ LTTNG_UST_FILTER ] = "Create Filter",
	[ LTTNG_UST_EXCLUSION ] = "Add exclusions to event",
};

static const char *str_timeout;
static int got_timeout_env;

extern void lttng_ring_buffer_client_overwrite_init(void);
extern void lttng_ring_buffer_client_overwrite_rt_init(void);
extern void lttng_ring_buffer_client_discard_init(void);
extern void lttng_ring_buffer_client_discard_rt_init(void);
extern void lttng_ring_buffer_metadata_client_init(void);
extern void lttng_ring_buffer_client_overwrite_exit(void);
extern void lttng_ring_buffer_client_overwrite_rt_exit(void);
extern void lttng_ring_buffer_client_discard_exit(void);
extern void lttng_ring_buffer_client_discard_rt_exit(void);
extern void lttng_ring_buffer_metadata_client_exit(void);

ssize_t lttng_ust_read(int fd, void *buf, size_t len)
{
	ssize_t ret;
	size_t copied = 0, to_copy = len;

	do {
		ret = read(fd, buf + copied, to_copy);
		if (ret > 0) {
			copied += ret;
			to_copy -= ret;
		}
	} while ((ret > 0 && to_copy > 0)
		|| (ret < 0 && errno == EINTR));
	if (ret > 0) {
		ret = copied;
	}
	return ret;
}
/*
 * Returns the HOME directory path. Caller MUST NOT free(3) the returned
 * pointer.
 */
static
const char *get_lttng_home_dir(void)
{
       const char *val;

       val = (const char *) lttng_getenv("LTTNG_HOME");
       if (val != NULL) {
               return val;
       }
       return (const char *) lttng_getenv("HOME");
}

/*
 * Force a read (imply TLS fixup for dlopen) of TLS variables.
 */
static
void lttng_fixup_nest_count_tls(void)
{
	asm volatile ("" : : "m" (URCU_TLS(lttng_ust_nest_count)));
}

static
void lttng_fixup_ust_mutex_nest_tls(void)
{
	asm volatile ("" : : "m" (URCU_TLS(ust_mutex_nest)));
}

/*
 * Fixup urcu bp TLS.
 */
static
void lttng_fixup_urcu_bp_tls(void)
{
	rcu_read_lock();
	rcu_read_unlock();
}

void lttng_ust_fixup_tls(void)
{
	lttng_fixup_urcu_bp_tls();
	lttng_fixup_ringbuffer_tls();
	lttng_fixup_vtid_tls();
	lttng_fixup_nest_count_tls();
	lttng_fixup_procname_tls();
	lttng_fixup_ust_mutex_nest_tls();
	lttng_ust_fixup_fd_tracker_tls();
}

int lttng_get_notify_socket(void *owner)
{
	struct sock_info *info = owner;

	return info->notify_socket;
}

static
void print_cmd(int cmd, int handle)
{
	const char *cmd_name = "Unknown";

	if (cmd >= 0 && cmd < LTTNG_ARRAY_SIZE(cmd_name_mapping)
			&& cmd_name_mapping[cmd]) {
		cmd_name = cmd_name_mapping[cmd];
	}
	DBG("Message Received \"%s\" (%d), Handle \"%s\" (%d)",
		cmd_name, cmd,
		lttng_ust_obj_get_name(handle), handle);
}

static
int setup_local_apps(void)
{
	const char *home_dir;
	uid_t uid;

	uid = getuid();
	/*
	 * Disallow per-user tracing for setuid binaries.
	 */
	if (uid != geteuid()) {
		assert(local_apps.allowed == 0);
		return 0;
	}
	home_dir = get_lttng_home_dir();
	if (!home_dir) {
		WARN("HOME environment variable not set. Disabling LTTng-UST per-user tracing.");
		assert(local_apps.allowed == 0);
		return -ENOENT;
	}
	local_apps.allowed = 1;
	snprintf(local_apps.sock_path, PATH_MAX, "%s/%s/%s",
		home_dir,
		LTTNG_DEFAULT_HOME_RUNDIR,
		LTTNG_UST_SOCK_FILENAME);
	snprintf(local_apps.wait_shm_path, PATH_MAX, "/%s-%u",
		LTTNG_UST_WAIT_FILENAME,
		uid);
	return 0;
}

/*
 * Get socket timeout, in ms.
 * -1: wait forever. 0: don't wait. >0: timeout, in ms.
 */
static
long get_timeout(void)
{
	long constructor_delay_ms = LTTNG_UST_DEFAULT_CONSTRUCTOR_TIMEOUT_MS;

	if (!got_timeout_env) {
		str_timeout = lttng_getenv("LTTNG_UST_REGISTER_TIMEOUT");
		got_timeout_env = 1;
	}
	if (str_timeout)
		constructor_delay_ms = strtol(str_timeout, NULL, 10);
	/* All negative values are considered as "-1". */
	if (constructor_delay_ms < -1)
		constructor_delay_ms = -1;
	return constructor_delay_ms;
}

/* Timeout for notify socket send and recv. */
static
long get_notify_sock_timeout(void)
{
	return get_timeout();
}

/* Timeout for connecting to cmd and notify sockets. */
static
long get_connect_sock_timeout(void)
{
	return get_timeout();
}

/*
 * Return values: -1: wait forever. 0: don't wait. 1: timeout wait.
 */
static
int get_constructor_timeout(struct timespec *constructor_timeout)
{
	long constructor_delay_ms;
	int ret;

	constructor_delay_ms = get_timeout();

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
		/* Don't wait. */
		return 0;
	}
	constructor_timeout->tv_sec += constructor_delay_ms / 1000UL;
	constructor_timeout->tv_nsec +=
		(constructor_delay_ms % 1000UL) * 1000000UL;
	if (constructor_timeout->tv_nsec >= 1000000000UL) {
		constructor_timeout->tv_sec++;
		constructor_timeout->tv_nsec -= 1000000000UL;
	}
	/* Timeout wait (constructor_delay_ms). */
	return 1;
}

static
void get_allow_blocking(void)
{
	const char *str_allow_blocking =
		lttng_getenv("LTTNG_UST_ALLOW_BLOCKING");

	if (str_allow_blocking) {
		DBG("%s environment variable is set",
			"LTTNG_UST_ALLOW_BLOCKING");
		lttng_ust_ringbuffer_set_allow_blocking();
	}
}

static
int register_to_sessiond(int socket, enum ustctl_socket_type type)
{
	return ustcomm_send_reg_msg(socket,
		type,
		CAA_BITS_PER_LONG,
		lttng_alignof(uint8_t) * CHAR_BIT,
		lttng_alignof(uint16_t) * CHAR_BIT,
		lttng_alignof(uint32_t) * CHAR_BIT,
		lttng_alignof(uint64_t) * CHAR_BIT,
		lttng_alignof(unsigned long) * CHAR_BIT);
}

static
int send_reply(int sock, struct ustcomm_ust_reply *lur)
{
	ssize_t len;

	len = ustcomm_send_unix_sock(sock, lur, sizeof(*lur));
	switch (len) {
	case sizeof(*lur):
		DBG("message successfully sent");
		return 0;
	default:
		if (len == -ECONNRESET) {
			DBG("remote end closed connection");
			return 0;
		}
		if (len < 0)
			return len;
		DBG("incorrect message size: %zd", len);
		return -EINVAL;
	}
}

static
int handle_register_done(struct sock_info *sock_info)
{
	int ret;

	if (sock_info->constructor_sem_posted)
		return 0;
	sock_info->constructor_sem_posted = 1;
	if (uatomic_read(&sem_count) <= 0) {
		return 0;
	}
	ret = uatomic_add_return(&sem_count, -1);
	if (ret == 0) {
		ret = sem_post(&constructor_wait);
		assert(!ret);
	}
	return 0;
}

/*
 * Only execute pending statedump after the constructor semaphore has
 * been posted by each listener thread. This means statedump will only
 * be performed after the "registration done" command is received from
 * each session daemon the application is connected to.
 *
 * This ensures we don't run into deadlock issues with the dynamic
 * loader mutex, which is held while the constructor is called and
 * waiting on the constructor semaphore. All operations requiring this
 * dynamic loader lock need to be postponed using this mechanism.
 */
static
void handle_pending_statedump(struct sock_info *sock_info)
{
	int ctor_passed = sock_info->constructor_sem_posted;

	if (ctor_passed && sock_info->statedump_pending) {
		sock_info->statedump_pending = 0;
		pthread_mutex_lock(&ust_fork_mutex);
		lttng_handle_pending_statedump(sock_info);
		pthread_mutex_unlock(&ust_fork_mutex);
	}
}

static
int handle_message(struct sock_info *sock_info,
		int sock, struct ustcomm_ust_msg *lum)
{
	int ret = 0;
	const struct lttng_ust_objd_ops *ops;
	struct ustcomm_ust_reply lur;
	union ust_args args;
	char ctxstr[LTTNG_UST_SYM_NAME_LEN];	/* App context string. */
	ssize_t len;

	memset(&lur, 0, sizeof(lur));

	if (ust_lock()) {
		ret = -LTTNG_UST_ERR_EXITING;
		goto error;
	}

	ops = objd_ops(lum->handle);
	if (!ops) {
		ret = -ENOENT;
		goto error;
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
			ret = lttng_ust_objd_unref(lum->handle, 1);
		break;
	case LTTNG_UST_FILTER:
	{
		/* Receive filter data */
		struct lttng_ust_filter_bytecode_node *bytecode;

		if (lum->u.filter.data_size > FILTER_BYTECODE_MAX_LEN) {
			ERR("Filter data size is too large: %u bytes",
				lum->u.filter.data_size);
			ret = -EINVAL;
			goto error;
		}

		if (lum->u.filter.reloc_offset > lum->u.filter.data_size) {
			ERR("Filter reloc offset %u is not within data",
				lum->u.filter.reloc_offset);
			ret = -EINVAL;
			goto error;
		}

		bytecode = zmalloc(sizeof(*bytecode) + lum->u.filter.data_size);
		if (!bytecode) {
			ret = -ENOMEM;
			goto error;
		}
		len = ustcomm_recv_unix_sock(sock, bytecode->bc.data,
				lum->u.filter.data_size);
		switch (len) {
		case 0:	/* orderly shutdown */
			ret = 0;
			free(bytecode);
			goto error;
		default:
			if (len == lum->u.filter.data_size) {
				DBG("filter data received");
				break;
			} else if (len < 0) {
				DBG("Receive failed from lttng-sessiond with errno %d", (int) -len);
				if (len == -ECONNRESET) {
					ERR("%s remote end closed connection", sock_info->name);
					ret = len;
					free(bytecode);
					goto error;
				}
				ret = len;
				free(bytecode);
				goto error;
			} else {
				DBG("incorrect filter data message size: %zd", len);
				ret = -EINVAL;
				free(bytecode);
				goto error;
			}
		}
		bytecode->bc.len = lum->u.filter.data_size;
		bytecode->bc.reloc_offset = lum->u.filter.reloc_offset;
		bytecode->bc.seqnum = lum->u.filter.seqnum;
		if (ops->cmd) {
			ret = ops->cmd(lum->handle, lum->cmd,
					(unsigned long) bytecode,
					&args, sock_info);
			if (ret) {
				free(bytecode);
			}
			/* don't free bytecode if everything went fine. */
		} else {
			ret = -ENOSYS;
			free(bytecode);
		}
		break;
	}
	case LTTNG_UST_EXCLUSION:
	{
		/* Receive exclusion names */
		struct lttng_ust_excluder_node *node;
		unsigned int count;

		count = lum->u.exclusion.count;
		if (count == 0) {
			/* There are no names to read */
			ret = 0;
			goto error;
		}
		node = zmalloc(sizeof(*node) +
				count * LTTNG_UST_SYM_NAME_LEN);
		if (!node) {
			ret = -ENOMEM;
			goto error;
		}
		node->excluder.count = count;
		len = ustcomm_recv_unix_sock(sock, node->excluder.names,
				count * LTTNG_UST_SYM_NAME_LEN);
		switch (len) {
		case 0:	/* orderly shutdown */
			ret = 0;
			free(node);
			goto error;
		default:
			if (len == count * LTTNG_UST_SYM_NAME_LEN) {
				DBG("Exclusion data received");
				break;
			} else if (len < 0) {
				DBG("Receive failed from lttng-sessiond with errno %d", (int) -len);
				if (len == -ECONNRESET) {
					ERR("%s remote end closed connection", sock_info->name);
					ret = len;
					free(node);
					goto error;
				}
				ret = len;
				free(node);
				goto error;
			} else {
				DBG("Incorrect exclusion data message size: %zd", len);
				ret = -EINVAL;
				free(node);
				goto error;
			}
		}
		if (ops->cmd) {
			ret = ops->cmd(lum->handle, lum->cmd,
					(unsigned long) node,
					&args, sock_info);
			if (ret) {
				free(node);
			}
			/* Don't free exclusion data if everything went fine. */
		} else {
			ret = -ENOSYS;
			free(node);
		}
		break;
	}
	case LTTNG_UST_CHANNEL:
	{
		void *chan_data;
		int wakeup_fd;

		len = ustcomm_recv_channel_from_sessiond(sock,
				&chan_data, lum->u.channel.len,
				&wakeup_fd);
		switch (len) {
		case 0:	/* orderly shutdown */
			ret = 0;
			goto error;
		default:
			if (len == lum->u.channel.len) {
				DBG("channel data received");
				break;
			} else if (len < 0) {
				DBG("Receive failed from lttng-sessiond with errno %d", (int) -len);
				if (len == -ECONNRESET) {
					ERR("%s remote end closed connection", sock_info->name);
					ret = len;
					goto error;
				}
				ret = len;
				goto error;
			} else {
				DBG("incorrect channel data message size: %zd", len);
				ret = -EINVAL;
				goto error;
			}
		}
		args.channel.chan_data = chan_data;
		args.channel.wakeup_fd = wakeup_fd;
		if (ops->cmd)
			ret = ops->cmd(lum->handle, lum->cmd,
					(unsigned long) &lum->u,
					&args, sock_info);
		else
			ret = -ENOSYS;
		break;
	}
	case LTTNG_UST_STREAM:
	{
		/* Receive shm_fd, wakeup_fd */
		ret = ustcomm_recv_stream_from_sessiond(sock,
			&lum->u.stream.len,
			&args.stream.shm_fd,
			&args.stream.wakeup_fd);
		if (ret) {
			goto error;
		}
		if (ops->cmd)
			ret = ops->cmd(lum->handle, lum->cmd,
					(unsigned long) &lum->u,
					&args, sock_info);
		else
			ret = -ENOSYS;
		break;
	}
	case LTTNG_UST_CONTEXT:
		switch (lum->u.context.ctx) {
		case LTTNG_UST_CONTEXT_APP_CONTEXT:
		{
			char *p;
			size_t ctxlen, recvlen;

			ctxlen = strlen("$app.") + lum->u.context.u.app_ctx.provider_name_len - 1
					+ strlen(":") + lum->u.context.u.app_ctx.ctx_name_len;
			if (ctxlen >= LTTNG_UST_SYM_NAME_LEN) {
				ERR("Application context string length size is too large: %zu bytes",
					ctxlen);
				ret = -EINVAL;
				goto error;
			}
			strcpy(ctxstr, "$app.");
			p = &ctxstr[strlen("$app.")];
			recvlen = ctxlen - strlen("$app.");
			len = ustcomm_recv_unix_sock(sock, p, recvlen);
			switch (len) {
			case 0:	/* orderly shutdown */
				ret = 0;
				goto error;
			default:
				if (len == recvlen) {
					DBG("app context data received");
					break;
				} else if (len < 0) {
					DBG("Receive failed from lttng-sessiond with errno %d", (int) -len);
					if (len == -ECONNRESET) {
						ERR("%s remote end closed connection", sock_info->name);
						ret = len;
						goto error;
					}
					ret = len;
					goto error;
				} else {
					DBG("incorrect app context data message size: %zd", len);
					ret = -EINVAL;
					goto error;
				}
			}
			/* Put : between provider and ctxname. */
			p[lum->u.context.u.app_ctx.provider_name_len - 1] = ':';
			args.app_context.ctxname = ctxstr;
			break;
		}
		default:
			break;
		}
		if (ops->cmd) {
			ret = ops->cmd(lum->handle, lum->cmd,
					(unsigned long) &lum->u,
					&args, sock_info);
		} else {
			ret = -ENOSYS;
		}
		break;
	default:
		if (ops->cmd)
			ret = ops->cmd(lum->handle, lum->cmd,
					(unsigned long) &lum->u,
					&args, sock_info);
		else
			ret = -ENOSYS;
		break;
	}

	lur.handle = lum->handle;
	lur.cmd = lum->cmd;
	lur.ret_val = ret;
	if (ret >= 0) {
		lur.ret_code = LTTNG_UST_OK;
	} else {
		/*
		 * Use -LTTNG_UST_ERR as wildcard for UST internal
		 * error that are not caused by the transport, except if
		 * we already have a more precise error message to
		 * report.
		 */
		if (ret > -LTTNG_UST_ERR) {
			/* Translate code to UST error. */
			switch (ret) {
			case -EEXIST:
				lur.ret_code = -LTTNG_UST_ERR_EXIST;
				break;
			case -EINVAL:
				lur.ret_code = -LTTNG_UST_ERR_INVAL;
				break;
			case -ENOENT:
				lur.ret_code = -LTTNG_UST_ERR_NOENT;
				break;
			case -EPERM:
				lur.ret_code = -LTTNG_UST_ERR_PERM;
				break;
			case -ENOSYS:
				lur.ret_code = -LTTNG_UST_ERR_NOSYS;
				break;
			default:
				lur.ret_code = -LTTNG_UST_ERR;
				break;
			}
		} else {
			lur.ret_code = ret;
		}
	}
	if (ret >= 0) {
		switch (lum->cmd) {
		case LTTNG_UST_TRACER_VERSION:
			lur.u.version = lum->u.version;
			break;
		case LTTNG_UST_TRACEPOINT_LIST_GET:
			memcpy(&lur.u.tracepoint, &lum->u.tracepoint, sizeof(lur.u.tracepoint));
			break;
		}
	}
	DBG("Return value: %d", lur.ret_val);

	ust_unlock();

	/*
	 * Performed delayed statedump operations outside of the UST
	 * lock. We need to take the dynamic loader lock before we take
	 * the UST lock internally within handle_pending_statedump().
	  */
	handle_pending_statedump(sock_info);

	if (ust_lock()) {
		ret = -LTTNG_UST_ERR_EXITING;
		goto error;
	}

	ret = send_reply(sock, &lur);
	if (ret < 0) {
		DBG("error sending reply");
		goto error;
	}

	/*
	 * LTTNG_UST_TRACEPOINT_FIELD_LIST_GET needs to send the field
	 * after the reply.
	 */
	if (lur.ret_code == LTTNG_UST_OK) {
		switch (lum->cmd) {
		case LTTNG_UST_TRACEPOINT_FIELD_LIST_GET:
			len = ustcomm_send_unix_sock(sock,
				&args.field_list.entry,
				sizeof(args.field_list.entry));
			if (len < 0) {
				ret = len;
				goto error;
			}
			if (len != sizeof(args.field_list.entry)) {
				ret = -EINVAL;
				goto error;
			}
		}
	}

error:
	ust_unlock();

	return ret;
}

static
void cleanup_sock_info(struct sock_info *sock_info, int exiting)
{
	int ret;

	if (sock_info->root_handle != -1) {
		ret = lttng_ust_objd_unref(sock_info->root_handle, 1);
		if (ret) {
			ERR("Error unref root handle");
		}
		sock_info->root_handle = -1;
	}
	sock_info->constructor_sem_posted = 0;

	/*
	 * wait_shm_mmap, socket and notify socket are used by listener
	 * threads outside of the ust lock, so we cannot tear them down
	 * ourselves, because we cannot join on these threads. Leave
	 * responsibility of cleaning up these resources to the OS
	 * process exit.
	 */
	if (exiting)
		return;

	if (sock_info->socket != -1) {
		ret = ustcomm_close_unix_sock(sock_info->socket);
		if (ret) {
			ERR("Error closing ust cmd socket");
		}
		sock_info->socket = -1;
	}
	if (sock_info->notify_socket != -1) {
		ret = ustcomm_close_unix_sock(sock_info->notify_socket);
		if (ret) {
			ERR("Error closing ust notify socket");
		}
		sock_info->notify_socket = -1;
	}
	if (sock_info->wait_shm_mmap) {
		long page_size;

		page_size = sysconf(_SC_PAGE_SIZE);
		if (page_size <= 0) {
			if (!page_size) {
				errno = EINVAL;
			}
			PERROR("Error in sysconf(_SC_PAGE_SIZE)");
		} else {
			ret = munmap(sock_info->wait_shm_mmap, page_size);
			if (ret) {
				ERR("Error unmapping wait shm");
			}
		}
		sock_info->wait_shm_mmap = NULL;
	}
}

/*
 * Using fork to set umask in the child process (not multi-thread safe).
 * We deal with the shm_open vs ftruncate race (happening when the
 * sessiond owns the shm and does not let everybody modify it, to ensure
 * safety against shm_unlink) by simply letting the mmap fail and
 * retrying after a few seconds.
 * For global shm, everybody has rw access to it until the sessiond
 * starts.
 */
static
int get_wait_shm(struct sock_info *sock_info, size_t mmap_size)
{
	int wait_shm_fd, ret;
	pid_t pid;

	/*
	 * Try to open read-only.
	 */
	wait_shm_fd = shm_open(sock_info->wait_shm_path, O_RDONLY, 0);
	if (wait_shm_fd >= 0) {
		int32_t tmp_read;
		ssize_t len;
		size_t bytes_read = 0;

		/*
		 * Try to read the fd. If unable to do so, try opening
		 * it in write mode.
		 */
		do {
			len = read(wait_shm_fd,
				&((char *) &tmp_read)[bytes_read],
				sizeof(tmp_read) - bytes_read);
			if (len > 0) {
				bytes_read += len;
			}
		} while ((len < 0 && errno == EINTR)
			|| (len > 0 && bytes_read < sizeof(tmp_read)));
		if (bytes_read != sizeof(tmp_read)) {
			ret = close(wait_shm_fd);
			if (ret) {
				ERR("close wait_shm_fd");
			}
			goto open_write;
		}
		goto end;
	} else if (wait_shm_fd < 0 && errno != ENOENT) {
		/*
		 * Real-only open did not work, and it's not because the
		 * entry was not present. It's a failure that prohibits
		 * using shm.
		 */
		ERR("Error opening shm %s", sock_info->wait_shm_path);
		goto end;
	}

open_write:
	/*
	 * If the open failed because the file did not exist, or because
	 * the file was not truncated yet, try creating it ourself.
	 */
	URCU_TLS(lttng_ust_nest_count)++;
	pid = fork();
	URCU_TLS(lttng_ust_nest_count)--;
	if (pid > 0) {
		int status;

		/*
		 * Parent: wait for child to return, in which case the
		 * shared memory map will have been created.
		 */
		pid = wait(&status);
		if (pid < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
			wait_shm_fd = -1;
			goto end;
		}
		/*
		 * Try to open read-only again after creation.
		 */
		wait_shm_fd = shm_open(sock_info->wait_shm_path, O_RDONLY, 0);
		if (wait_shm_fd < 0) {
			/*
			 * Real-only open did not work. It's a failure
			 * that prohibits using shm.
			 */
			ERR("Error opening shm %s", sock_info->wait_shm_path);
			goto end;
		}
		goto end;
	} else if (pid == 0) {
		int create_mode;

		/* Child */
		create_mode = S_IRUSR | S_IWUSR | S_IRGRP;
		if (sock_info->global)
			create_mode |= S_IROTH | S_IWGRP | S_IWOTH;
		/*
		 * We're alone in a child process, so we can modify the
		 * process-wide umask.
		 */
		umask(~create_mode);
		/*
		 * Try creating shm (or get rw access).
		 * We don't do an exclusive open, because we allow other
		 * processes to create+ftruncate it concurrently.
		 */
		wait_shm_fd = shm_open(sock_info->wait_shm_path,
				O_RDWR | O_CREAT, create_mode);
		if (wait_shm_fd >= 0) {
			ret = ftruncate(wait_shm_fd, mmap_size);
			if (ret) {
				PERROR("ftruncate");
				_exit(EXIT_FAILURE);
			}
			_exit(EXIT_SUCCESS);
		}
		/*
		 * For local shm, we need to have rw access to accept
		 * opening it: this means the local sessiond will be
		 * able to wake us up. For global shm, we open it even
		 * if rw access is not granted, because the root.root
		 * sessiond will be able to override all rights and wake
		 * us up.
		 */
		if (!sock_info->global && errno != EACCES) {
			ERR("Error opening shm %s", sock_info->wait_shm_path);
			_exit(EXIT_FAILURE);
		}
		/*
		 * The shm exists, but we cannot open it RW. Report
		 * success.
		 */
		_exit(EXIT_SUCCESS);
	} else {
		return -1;
	}
end:
	if (wait_shm_fd >= 0 && !sock_info->global) {
		struct stat statbuf;

		/*
		 * Ensure that our user is the owner of the shm file for
		 * local shm. If we do not own the file, it means our
		 * sessiond will not have access to wake us up (there is
		 * probably a rogue process trying to fake our
		 * sessiond). Fallback to polling method in this case.
		 */
		ret = fstat(wait_shm_fd, &statbuf);
		if (ret) {
			PERROR("fstat");
			goto error_close;
		}
		if (statbuf.st_uid != getuid())
			goto error_close;
	}
	return wait_shm_fd;

error_close:
	ret = close(wait_shm_fd);
	if (ret) {
		PERROR("Error closing fd");
	}
	return -1;
}

static
char *get_map_shm(struct sock_info *sock_info)
{
	long page_size;
	int wait_shm_fd, ret;
	char *wait_shm_mmap;

	page_size = sysconf(_SC_PAGE_SIZE);
	if (page_size <= 0) {
		if (!page_size) {
			errno = EINVAL;
		}
		PERROR("Error in sysconf(_SC_PAGE_SIZE)");
		goto error;
	}

	lttng_ust_lock_fd_tracker();
	wait_shm_fd = get_wait_shm(sock_info, page_size);
	if (wait_shm_fd < 0) {
		lttng_ust_unlock_fd_tracker();
		goto error;
	}
	lttng_ust_add_fd_to_tracker(wait_shm_fd);
	lttng_ust_unlock_fd_tracker();

	wait_shm_mmap = mmap(NULL, page_size, PROT_READ,
		  MAP_SHARED, wait_shm_fd, 0);

	/* close shm fd immediately after taking the mmap reference */
	lttng_ust_lock_fd_tracker();
	ret = close(wait_shm_fd);
	if (!ret) {
		lttng_ust_delete_fd_from_tracker(wait_shm_fd);
	} else {
		PERROR("Error closing fd");
	}
	lttng_ust_unlock_fd_tracker();

	if (wait_shm_mmap == MAP_FAILED) {
		DBG("mmap error (can be caused by race with sessiond). Fallback to poll mode.");
		goto error;
	}
	return wait_shm_mmap;

error:
	return NULL;
}

static
void wait_for_sessiond(struct sock_info *sock_info)
{
	if (ust_lock()) {
		goto quit;
	}
	if (wait_poll_fallback) {
		goto error;
	}
	if (!sock_info->wait_shm_mmap) {
		sock_info->wait_shm_mmap = get_map_shm(sock_info);
		if (!sock_info->wait_shm_mmap)
			goto error;
	}
	ust_unlock();

	DBG("Waiting for %s apps sessiond", sock_info->name);
	/* Wait for futex wakeup */
	if (uatomic_read((int32_t *) sock_info->wait_shm_mmap))
		goto end_wait;

	while (futex_async((int32_t *) sock_info->wait_shm_mmap,
			FUTEX_WAIT, 0, NULL, NULL, 0)) {
		switch (errno) {
		case EWOULDBLOCK:
			/* Value already changed. */
			goto end_wait;
		case EINTR:
			/* Retry if interrupted by signal. */
			break;	/* Get out of switch. */
		case EFAULT:
			wait_poll_fallback = 1;
			DBG(
"Linux kernels 2.6.33 to 3.0 (with the exception of stable versions) "
"do not support FUTEX_WAKE on read-only memory mappings correctly. "
"Please upgrade your kernel "
"(fix is commit 9ea71503a8ed9184d2d0b8ccc4d269d05f7940ae in Linux kernel "
"mainline). LTTng-UST will use polling mode fallback.");
			if (ust_debug())
				PERROR("futex");
			goto end_wait;
		}
	}
end_wait:
	return;

quit:
	ust_unlock();
	return;

error:
	ust_unlock();
	return;
}

/*
 * This thread does not allocate any resource, except within
 * handle_message, within mutex protection. This mutex protects against
 * fork and exit.
 * The other moment it allocates resources is at socket connection, which
 * is also protected by the mutex.
 */
static
void *ust_listener_thread(void *arg)
{
	struct sock_info *sock_info = arg;
	int sock, ret, prev_connect_failed = 0, has_waited = 0;
	long timeout;

	lttng_ust_fixup_tls();
	/*
	 * If available, add '-ust' to the end of this thread's
	 * process name
	 */
	ret = lttng_ust_setustprocname();
	if (ret) {
		ERR("Unable to set UST process name");
	}

	/* Restart trying to connect to the session daemon */
restart:
	if (prev_connect_failed) {
		/* Wait for sessiond availability with pipe */
		wait_for_sessiond(sock_info);
		if (has_waited) {
			has_waited = 0;
			/*
			 * Sleep for 5 seconds before retrying after a
			 * sequence of failure / wait / failure. This
			 * deals with a killed or broken session daemon.
			 */
			sleep(5);
		} else {
			has_waited = 1;
		}
		prev_connect_failed = 0;
	}

	if (sock_info->socket != -1) {
		/* FD tracker is updated by ustcomm_close_unix_sock() */
		ret = ustcomm_close_unix_sock(sock_info->socket);
		if (ret) {
			ERR("Error closing %s ust cmd socket",
				sock_info->name);
		}
		sock_info->socket = -1;
	}
	if (sock_info->notify_socket != -1) {
		/* FD tracker is updated by ustcomm_close_unix_sock() */
		ret = ustcomm_close_unix_sock(sock_info->notify_socket);
		if (ret) {
			ERR("Error closing %s ust notify socket",
				sock_info->name);
		}
		sock_info->notify_socket = -1;
	}

	if (ust_lock()) {
		goto quit;
	}

	/*
	 * Register. We need to perform both connect and sending
	 * registration message before doing the next connect otherwise
	 * we may reach unix socket connect queue max limits and block
	 * on the 2nd connect while the session daemon is awaiting the
	 * first connect registration message.
	 */
	/* Connect cmd socket */
	lttng_ust_lock_fd_tracker();
	ret = ustcomm_connect_unix_sock(sock_info->sock_path,
		get_connect_sock_timeout());
	if (ret < 0) {
		lttng_ust_unlock_fd_tracker();
		DBG("Info: sessiond not accepting connections to %s apps socket", sock_info->name);
		prev_connect_failed = 1;

		/*
		 * If we cannot find the sessiond daemon, don't delay
		 * constructor execution.
		 */
		ret = handle_register_done(sock_info);
		assert(!ret);
		ust_unlock();
		goto restart;
	}
	lttng_ust_add_fd_to_tracker(ret);
	lttng_ust_unlock_fd_tracker();
	sock_info->socket = ret;

	ust_unlock();
	/*
	 * Unlock/relock ust lock because connect is blocking (with
	 * timeout). Don't delay constructors on the ust lock for too
	 * long.
	 */
	if (ust_lock()) {
		goto quit;
	}

	/*
	 * Create only one root handle per listener thread for the whole
	 * process lifetime, so we ensure we get ID which is statically
	 * assigned to the root handle.
	 */
	if (sock_info->root_handle == -1) {
		ret = lttng_abi_create_root_handle();
		if (ret < 0) {
			ERR("Error creating root handle");
			goto quit;
		}
		sock_info->root_handle = ret;
	}

	ret = register_to_sessiond(sock_info->socket, USTCTL_SOCKET_CMD);
	if (ret < 0) {
		ERR("Error registering to %s ust cmd socket",
			sock_info->name);
		prev_connect_failed = 1;
		/*
		 * If we cannot register to the sessiond daemon, don't
		 * delay constructor execution.
		 */
		ret = handle_register_done(sock_info);
		assert(!ret);
		ust_unlock();
		goto restart;
	}

	ust_unlock();
	/*
	 * Unlock/relock ust lock because connect is blocking (with
	 * timeout). Don't delay constructors on the ust lock for too
	 * long.
	 */
	if (ust_lock()) {
		goto quit;
	}

	/* Connect notify socket */
	lttng_ust_lock_fd_tracker();
	ret = ustcomm_connect_unix_sock(sock_info->sock_path,
		get_connect_sock_timeout());
	if (ret < 0) {
		lttng_ust_unlock_fd_tracker();
		DBG("Info: sessiond not accepting connections to %s apps socket", sock_info->name);
		prev_connect_failed = 1;

		/*
		 * If we cannot find the sessiond daemon, don't delay
		 * constructor execution.
		 */
		ret = handle_register_done(sock_info);
		assert(!ret);
		ust_unlock();
		goto restart;
	}
	lttng_ust_add_fd_to_tracker(ret);
	lttng_ust_unlock_fd_tracker();
	sock_info->notify_socket = ret;

	ust_unlock();
	/*
	 * Unlock/relock ust lock because connect is blocking (with
	 * timeout). Don't delay constructors on the ust lock for too
	 * long.
	 */
	if (ust_lock()) {
		goto quit;
	}

	timeout = get_notify_sock_timeout();
	if (timeout >= 0) {
		/*
		 * Give at least 10ms to sessiond to reply to
		 * notifications.
		 */
		if (timeout < 10)
			timeout = 10;
		ret = ustcomm_setsockopt_rcv_timeout(sock_info->notify_socket,
				timeout);
		if (ret < 0) {
			WARN("Error setting socket receive timeout");
		}
		ret = ustcomm_setsockopt_snd_timeout(sock_info->notify_socket,
				timeout);
		if (ret < 0) {
			WARN("Error setting socket send timeout");
		}
	} else if (timeout < -1) {
		WARN("Unsupported timeout value %ld", timeout);
	}

	ret = register_to_sessiond(sock_info->notify_socket,
			USTCTL_SOCKET_NOTIFY);
	if (ret < 0) {
		ERR("Error registering to %s ust notify socket",
			sock_info->name);
		prev_connect_failed = 1;
		/*
		 * If we cannot register to the sessiond daemon, don't
		 * delay constructor execution.
		 */
		ret = handle_register_done(sock_info);
		assert(!ret);
		ust_unlock();
		goto restart;
	}
	sock = sock_info->socket;

	ust_unlock();

	for (;;) {
		ssize_t len;
		struct ustcomm_ust_msg lum;

		len = ustcomm_recv_unix_sock(sock, &lum, sizeof(lum));
		switch (len) {
		case 0:	/* orderly shutdown */
			DBG("%s lttng-sessiond has performed an orderly shutdown", sock_info->name);
			if (ust_lock()) {
				goto quit;
			}
			/*
			 * Either sessiond has shutdown or refused us by closing the socket.
			 * In either case, we don't want to delay construction execution,
			 * and we need to wait before retry.
			 */
			prev_connect_failed = 1;
			/*
			 * If we cannot register to the sessiond daemon, don't
			 * delay constructor execution.
			 */
			ret = handle_register_done(sock_info);
			assert(!ret);
			ust_unlock();
			goto end;
		case sizeof(lum):
			print_cmd(lum.cmd, lum.handle);
			ret = handle_message(sock_info, sock, &lum);
			if (ret) {
				ERR("Error handling message for %s socket",
					sock_info->name);
				/*
				 * Close socket if protocol error is
				 * detected.
				 */
				goto end;
			}
			continue;
		default:
			if (len < 0) {
				DBG("Receive failed from lttng-sessiond with errno %d", (int) -len);
			} else {
				DBG("incorrect message size (%s socket): %zd", sock_info->name, len);
			}
			if (len == -ECONNRESET) {
				DBG("%s remote end closed connection", sock_info->name);
				goto end;
			}
			goto end;
		}

	}
end:
	if (ust_lock()) {
		goto quit;
	}
	/* Cleanup socket handles before trying to reconnect */
	lttng_ust_objd_table_owner_cleanup(sock_info);
	ust_unlock();
	goto restart;	/* try to reconnect */

quit:
	ust_unlock();

	pthread_mutex_lock(&ust_exit_mutex);
	sock_info->thread_active = 0;
	pthread_mutex_unlock(&ust_exit_mutex);
	return NULL;
}

/*
 * Weak symbol to call when the ust malloc wrapper is not loaded.
 */
__attribute__((weak))
void lttng_ust_malloc_wrapper_init(void)
{
}

/*
 * sessiond monitoring thread: monitor presence of global and per-user
 * sessiond by polling the application common named pipe.
 */
void __attribute__((constructor)) lttng_ust_init(void)
{
	struct timespec constructor_timeout;
	sigset_t sig_all_blocked, orig_parent_mask;
	pthread_attr_t thread_attr;
	int timeout_mode;
	int ret;

	if (uatomic_xchg(&initialized, 1) == 1)
		return;

	/*
	 * Fixup interdependency between TLS fixup mutex (which happens
	 * to be the dynamic linker mutex) and ust_lock, taken within
	 * the ust lock.
	 */
	lttng_ust_fixup_tls();

	lttng_ust_loaded = 1;

	/*
	 * We want precise control over the order in which we construct
	 * our sub-libraries vs starting to receive commands from
	 * sessiond (otherwise leading to errors when trying to create
	 * sessiond before the init functions are completed).
	 */
	init_usterr();
	lttng_ust_getenv_init();	/* Needs init_usterr() to be completed. */
	init_tracepoint();
	lttng_ust_init_fd_tracker();
	lttng_ust_clock_init();
	lttng_ust_getcpu_init();
	lttng_ust_statedump_init();
	lttng_ring_buffer_metadata_client_init();
	lttng_ring_buffer_client_overwrite_init();
	lttng_ring_buffer_client_overwrite_rt_init();
	lttng_ring_buffer_client_discard_init();
	lttng_ring_buffer_client_discard_rt_init();
	lttng_perf_counter_init();
	/*
	 * Invoke ust malloc wrapper init before starting other threads.
	 */
	lttng_ust_malloc_wrapper_init();

	timeout_mode = get_constructor_timeout(&constructor_timeout);

	get_allow_blocking();

	ret = sem_init(&constructor_wait, 0, 0);
	if (ret) {
		PERROR("sem_init");
	}

	ret = setup_local_apps();
	if (ret) {
		DBG("local apps setup returned %d", ret);
	}

	/* A new thread created by pthread_create inherits the signal mask
	 * from the parent. To avoid any signal being received by the
	 * listener thread, we block all signals temporarily in the parent,
	 * while we create the listener thread.
	 */
	sigfillset(&sig_all_blocked);
	ret = pthread_sigmask(SIG_SETMASK, &sig_all_blocked, &orig_parent_mask);
	if (ret) {
		ERR("pthread_sigmask: %s", strerror(ret));
	}

	ret = pthread_attr_init(&thread_attr);
	if (ret) {
		ERR("pthread_attr_init: %s", strerror(ret));
	}
	ret = pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
	if (ret) {
		ERR("pthread_attr_setdetachstate: %s", strerror(ret));
	}

	pthread_mutex_lock(&ust_exit_mutex);
	ret = pthread_create(&global_apps.ust_listener, &thread_attr,
			ust_listener_thread, &global_apps);
	if (ret) {
		ERR("pthread_create global: %s", strerror(ret));
	}
	global_apps.thread_active = 1;
	pthread_mutex_unlock(&ust_exit_mutex);

	if (local_apps.allowed) {
		pthread_mutex_lock(&ust_exit_mutex);
		ret = pthread_create(&local_apps.ust_listener, &thread_attr,
				ust_listener_thread, &local_apps);
		if (ret) {
			ERR("pthread_create local: %s", strerror(ret));
		}
		local_apps.thread_active = 1;
		pthread_mutex_unlock(&ust_exit_mutex);
	} else {
		handle_register_done(&local_apps);
	}
	ret = pthread_attr_destroy(&thread_attr);
	if (ret) {
		ERR("pthread_attr_destroy: %s", strerror(ret));
	}

	/* Restore original signal mask in parent */
	ret = pthread_sigmask(SIG_SETMASK, &orig_parent_mask, NULL);
	if (ret) {
		ERR("pthread_sigmask: %s", strerror(ret));
	}

	switch (timeout_mode) {
	case 1:	/* timeout wait */
		do {
			ret = sem_timedwait(&constructor_wait,
					&constructor_timeout);
		} while (ret < 0 && errno == EINTR);
		if (ret < 0) {
			switch (errno) {
			case ETIMEDOUT:
				ERR("Timed out waiting for lttng-sessiond");
				break;
			case EINVAL:
				PERROR("sem_timedwait");
				break;
			default:
				ERR("Unexpected error \"%s\" returned by sem_timedwait",
					strerror(errno));
			}
		}
		break;
	case -1:/* wait forever */
		do {
			ret = sem_wait(&constructor_wait);
		} while (ret < 0 && errno == EINTR);
		if (ret < 0) {
			switch (errno) {
			case EINVAL:
				PERROR("sem_wait");
				break;
			default:
				ERR("Unexpected error \"%s\" returned by sem_wait",
					strerror(errno));
			}
		}
		break;
	case 0:	/* no timeout */
		break;
	}
}

static
void lttng_ust_cleanup(int exiting)
{
	cleanup_sock_info(&global_apps, exiting);
	cleanup_sock_info(&local_apps, exiting);
	local_apps.allowed = 0;
	/*
	 * The teardown in this function all affect data structures
	 * accessed under the UST lock by the listener thread. This
	 * lock, along with the lttng_ust_comm_should_quit flag, ensure
	 * that none of these threads are accessing this data at this
	 * point.
	 */
	lttng_ust_abi_exit();
	lttng_ust_events_exit();
	lttng_perf_counter_exit();
	lttng_ring_buffer_client_discard_rt_exit();
	lttng_ring_buffer_client_discard_exit();
	lttng_ring_buffer_client_overwrite_rt_exit();
	lttng_ring_buffer_client_overwrite_exit();
	lttng_ring_buffer_metadata_client_exit();
	lttng_ust_statedump_destroy();
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
	ust_lock_nocheck();
	lttng_ust_comm_should_quit = 1;
	ust_unlock();

	pthread_mutex_lock(&ust_exit_mutex);
	/* cancel threads */
	if (global_apps.thread_active) {
		ret = pthread_cancel(global_apps.ust_listener);
		if (ret) {
			ERR("Error cancelling global ust listener thread: %s",
				strerror(ret));
		} else {
			global_apps.thread_active = 0;
		}
	}
	if (local_apps.thread_active) {
		ret = pthread_cancel(local_apps.ust_listener);
		if (ret) {
			ERR("Error cancelling local ust listener thread: %s",
				strerror(ret));
		} else {
			local_apps.thread_active = 0;
		}
	}
	pthread_mutex_unlock(&ust_exit_mutex);

	/*
	 * Do NOT join threads: use of sys_futex makes it impossible to
	 * join the threads without using async-cancel, but async-cancel
	 * is delivered by a signal, which could hit the target thread
	 * anywhere in its code path, including while the ust_lock() is
	 * held, causing a deadlock for the other thread. Let the OS
	 * cleanup the threads if there are stalled in a syscall.
	 */
	lttng_ust_cleanup(1);
}

/*
 * We exclude the worker threads across fork and clone (except
 * CLONE_VM), because these system calls only keep the forking thread
 * running in the child.  Therefore, we don't want to call fork or clone
 * in the middle of an tracepoint or ust tracing state modification.
 * Holding this mutex protects these structures across fork and clone.
 */
void ust_before_fork(sigset_t *save_sigset)
{
	/*
	 * Disable signals. This is to avoid that the child intervenes
	 * before it is properly setup for tracing. It is safer to
	 * disable all signals, because then we know we are not breaking
	 * anything by restoring the original mask.
         */
	sigset_t all_sigs;
	int ret;

	/* Fixup lttng-ust TLS. */
	lttng_ust_fixup_tls();

	if (URCU_TLS(lttng_ust_nest_count))
		return;
	/* Disable signals */
	sigfillset(&all_sigs);
	ret = sigprocmask(SIG_BLOCK, &all_sigs, save_sigset);
	if (ret == -1) {
		PERROR("sigprocmask");
	}

	pthread_mutex_lock(&ust_fork_mutex);

	ust_lock_nocheck();
	rcu_bp_before_fork();
}

static void ust_after_fork_common(sigset_t *restore_sigset)
{
	int ret;

	DBG("process %d", getpid());
	ust_unlock();

	pthread_mutex_unlock(&ust_fork_mutex);

	/* Restore signals */
	ret = sigprocmask(SIG_SETMASK, restore_sigset, NULL);
	if (ret == -1) {
		PERROR("sigprocmask");
	}
}

void ust_after_fork_parent(sigset_t *restore_sigset)
{
	if (URCU_TLS(lttng_ust_nest_count))
		return;
	DBG("process %d", getpid());
	rcu_bp_after_fork_parent();
	/* Release mutexes and reenable signals */
	ust_after_fork_common(restore_sigset);
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
void ust_after_fork_child(sigset_t *restore_sigset)
{
	if (URCU_TLS(lttng_ust_nest_count))
		return;
	lttng_context_vtid_reset();
	DBG("process %d", getpid());
	/* Release urcu mutexes */
	rcu_bp_after_fork_child();
	lttng_ust_cleanup(0);
	/* Release mutexes and reenable signals */
	ust_after_fork_common(restore_sigset);
	lttng_ust_init();
}

void lttng_ust_sockinfo_session_enabled(void *owner)
{
	struct sock_info *sock_info = owner;
	sock_info->statedump_pending = 1;
}
