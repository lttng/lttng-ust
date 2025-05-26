/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011 EfficiOS Inc.
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#define _LGPL_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dlfcn.h>
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
#include <urcu/compiler.h>
#include <lttng/urcu/urcu-ust.h>

#include <lttng/ust-utils.h>
#include <lttng/ust-events.h>
#include <lttng/ust-abi.h>
#include <lttng/ust-fork.h>
#include <lttng/ust-error.h>
#include <lttng/ust-ctl.h>
#include <lttng/ust-libc-wrapper.h>
#include <lttng/ust-thread.h>
#include <lttng/ust-tracer.h>
#include <lttng/ust-common.h>
#include <lttng/ust-cancelstate.h>
#include <lttng/ust-fd.h>
#include <urcu/tls-compat.h>
#include "lib/lttng-ust/futex.h"
#include "common/ustcomm.h"
#include "common/logging.h"
#include "common/macros.h"
#include "common/tracepoint.h"
#include "lttng-tracer-core.h"
#include "common/compat/pthread.h"
#include "common/procname.h"
#include "common/ringbuffer/rb-init.h"
#include "lttng-ust-statedump.h"
#include "common/clock.h"
#include "common/getenv.h"
#include "lib/lttng-ust/events.h"
#include "context-internal.h"
#include "common/align.h"
#include "common/counter-clients/clients.h"
#include "common/ringbuffer-clients/clients.h"

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
 *
 * The ust fd tracker lock nests within the ust_mutex.
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
 * Notes on async-signal-safety of ust lock: a few libc functions are used
 * which are not strictly async-signal-safe:
 *
 * - pthread_setcancelstate
 * - pthread_mutex_lock
 * - pthread_mutex_unlock
 *
 * As of glibc 2.35, the implementation of pthread_setcancelstate only
 * touches TLS data, and it appears to be safe to use from signal
 * handlers. If the libc implementation changes, this will need to be
 * revisited, and we may ask glibc to provide an async-signal-safe
 * pthread_setcancelstate.
 *
 * As of glibc 2.35, the implementation of pthread_mutex_lock/unlock
 * for fast mutexes only relies on the pthread_mutex_t structure.
 * Disabling signals around all uses of this mutex ensures
 * signal-safety. If the libc implementation changes and eventually uses
 * other global resources, this will need to be revisited and we may
 * need to implement our own mutex.
 */

/*
 * Return 0 on success, -1 if should quit.
 * The lock is taken in both cases.
 * Signal-safe.
 */
int ust_lock(void)
{
	sigset_t sig_all_blocked, orig_mask;
	int ret;

	if (lttng_ust_cancelstate_disable_push()) {
		ERR("lttng_ust_cancelstate_disable_push");
	}
	sigfillset(&sig_all_blocked);
	ret = pthread_sigmask(SIG_SETMASK, &sig_all_blocked, &orig_mask);
	if (ret) {
		ERR("pthread_sigmask: ret=%d", ret);
	}
	if (!URCU_TLS(ust_mutex_nest)++)
		pthread_mutex_lock(&ust_mutex);
	ret = pthread_sigmask(SIG_SETMASK, &orig_mask, NULL);
	if (ret) {
		ERR("pthread_sigmask: ret=%d", ret);
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
	int ret;

	if (lttng_ust_cancelstate_disable_push()) {
		ERR("lttng_ust_cancelstate_disable_push");
	}
	sigfillset(&sig_all_blocked);
	ret = pthread_sigmask(SIG_SETMASK, &sig_all_blocked, &orig_mask);
	if (ret) {
		ERR("pthread_sigmask: ret=%d", ret);
	}
	if (!URCU_TLS(ust_mutex_nest)++)
		pthread_mutex_lock(&ust_mutex);
	ret = pthread_sigmask(SIG_SETMASK, &orig_mask, NULL);
	if (ret) {
		ERR("pthread_sigmask: ret=%d", ret);
	}
}

/*
 * Signal-safe.
 */
void ust_unlock(void)
{
	sigset_t sig_all_blocked, orig_mask;
	int ret;

	sigfillset(&sig_all_blocked);
	ret = pthread_sigmask(SIG_SETMASK, &sig_all_blocked, &orig_mask);
	if (ret) {
		ERR("pthread_sigmask: ret=%d", ret);
	}
	if (!--URCU_TLS(ust_mutex_nest))
		pthread_mutex_unlock(&ust_mutex);
	ret = pthread_sigmask(SIG_SETMASK, &orig_mask, NULL);
	if (ret) {
		ERR("pthread_sigmask: ret=%d", ret);
	}
	if (lttng_ust_cancelstate_disable_pop()) {
		ERR("lttng_ust_cancelstate_disable_pop");
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
 * Doing this for the ust_app, global and local sessiond.
 */
enum {
	sem_count_initial_value = 6,
};

static int sem_count = sem_count_initial_value;

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
	int registration_done;
	int allowed;
	bool multi_user;
	int thread_active;

	char sock_path[PATH_MAX];
	int socket;
	int notify_socket;

	/*
	 * If wait_shm_is_file is true, use standard open to open and
	 * create the shared memory used for waiting on session daemon.
	 * Otherwise, use shm_open to create this file.
	 */
	bool wait_shm_is_file;
	char wait_shm_path[PATH_MAX];
	char *wait_shm_mmap;

	/* Keep track of lazy state dump not performed yet. */
	int statedump_pending;
	int initial_statedump_done;
	/* Keep procname for statedump */
	char procname[LTTNG_UST_CONTEXT_PROCNAME_LEN];
};

/* Socket from app (connect) to session daemon (listen) for communication */
static struct sock_info ust_app = {
	.name = "ust_app",
	.multi_user = true,

	.root_handle = -1,
	.registration_done = 0,
	.allowed = 0,
	.thread_active = 0,

	.socket = -1,
	.notify_socket = -1,

	.wait_shm_is_file = true,

	.statedump_pending = 0,
	.initial_statedump_done = 0,
	.procname[0] = '\0'
};


static struct sock_info global_apps = {
	.name = "global",
	.multi_user = true,

	.root_handle = -1,
	.registration_done = 0,
	.allowed = 0,
	.thread_active = 0,

	.sock_path = LTTNG_DEFAULT_RUNDIR "/" LTTNG_UST_SOCK_FILENAME,
	.socket = -1,
	.notify_socket = -1,

	.wait_shm_is_file = false,
	.wait_shm_path = "/" LTTNG_UST_WAIT_FILENAME,

	.statedump_pending = 0,
	.initial_statedump_done = 0,
	.procname[0] = '\0'
};

static struct sock_info local_apps = {
	.name = "local",
	.multi_user = false,
	.root_handle = -1,
	.registration_done = 0,
	.allowed = 0,	/* Check setuid bit first */
	.thread_active = 0,

	.socket = -1,
	.notify_socket = -1,

	.wait_shm_is_file = false,

	.statedump_pending = 0,
	.initial_statedump_done = 0,
	.procname[0] = '\0'
};

static int wait_poll_fallback;

static const char *cmd_name_mapping[] = {
	[ LTTNG_UST_ABI_RELEASE ] = "Release",
	[ LTTNG_UST_ABI_SESSION ] = "Create Session",
	[ LTTNG_UST_ABI_TRACER_VERSION ] = "Get Tracer Version",

	[ LTTNG_UST_ABI_TRACEPOINT_LIST ] = "Create Tracepoint List",
	[ LTTNG_UST_ABI_WAIT_QUIESCENT ] = "Wait for Quiescent State",
	[ LTTNG_UST_ABI_REGISTER_DONE ] = "Registration Done",
	[ LTTNG_UST_ABI_TRACEPOINT_FIELD_LIST ] = "Create Tracepoint Field List",

	[ LTTNG_UST_ABI_EVENT_NOTIFIER_GROUP_CREATE ] = "Create event notifier group",

	/* Session FD commands */
	[ LTTNG_UST_ABI_CHANNEL ] = "Create Channel",
	[ LTTNG_UST_ABI_SESSION_START ] = "Start Session",
	[ LTTNG_UST_ABI_SESSION_STOP ] = "Stop Session",

	/* Channel FD commands */
	[ LTTNG_UST_ABI_STREAM ] = "Create Stream",
	[ LTTNG_UST_ABI_EVENT ] = "Create Event",

	/* Event and Channel FD commands */
	[ LTTNG_UST_ABI_CONTEXT ] = "Create Context",
	[ LTTNG_UST_ABI_FLUSH_BUFFER ] = "Flush Buffer",

	/* Event, Channel and Session commands */
	[ LTTNG_UST_ABI_ENABLE ] = "Enable",
	[ LTTNG_UST_ABI_DISABLE ] = "Disable",

	/* Tracepoint list commands */
	[ LTTNG_UST_ABI_TRACEPOINT_LIST_GET ] = "List Next Tracepoint",
	[ LTTNG_UST_ABI_TRACEPOINT_FIELD_LIST_GET ] = "List Next Tracepoint Field",

	/* Event FD commands */
	[ LTTNG_UST_ABI_FILTER ] = "Create Filter",
	[ LTTNG_UST_ABI_EXCLUSION ] = "Add exclusions to event",

	/* Event notifier group commands */
	[ LTTNG_UST_ABI_EVENT_NOTIFIER_CREATE ] = "Create event notifier",

	/* Session and event notifier group commands */
	[ LTTNG_UST_ABI_COUNTER ] = "Create Counter",

	/* Counter commands */
	[ LTTNG_UST_ABI_COUNTER_CHANNEL ] = "Create Counter Channel",
	[ LTTNG_UST_ABI_COUNTER_CPU ] = "Create Counter CPU",
#ifdef CONFIG_LTTNG_UST_EXPERIMENTAL_COUNTER
	[ LTTNG_UST_ABI_COUNTER_EVENT ] = "Create Counter Event",
#endif	/* CONFIG_LTTNG_UST_EXPERIMENTAL_COUNTER */
};

static const char *str_timeout;
static int got_timeout_env;

static char *get_map_shm(struct sock_info *sock_info);

/*
 * Returns the HOME directory path. Caller MUST NOT free(3) the returned
 * pointer.
 */
static
const char *get_lttng_home_dir(void)
{
       const char *val;

       val = (const char *) lttng_ust_getenv("LTTNG_HOME");
       if (val != NULL) {
               return val;
       }
       return (const char *) lttng_ust_getenv("HOME");
}

/*
 * Returns the LTTNG_UST_APP_PATH path. If environment variable exists
 * and contains a ':', the first path before the ':' separator is returned.
 * The return value should be freed by the caller if it is not NULL.
 */
static
char *get_lttng_ust_app_path(void)
{
	const char *env_val = lttng_ust_getenv("LTTNG_UST_APP_PATH");
	char *val = NULL;
	char *sep = NULL;
	if (env_val == NULL)
		goto error;
	sep = strchr((char*)env_val, ':');
	if (sep) {
		/*
		 * Split into multiple paths using ':' as a separator.
		 * There is no escaping of the ':' separator.
		 */
		WARN("':' separator in LTTNG_UST_APP_PATH, only the first path will be used.");
		val = zmalloc(sep - env_val + 1);
		if (!val) {
			PERROR("zmalloc get_lttng_ust_app_path");
			goto error;
		}
		memcpy(val, env_val, sep - env_val);
		val[sep - env_val] = '\0';
	} else {
		val = strdup(env_val);
		if (!val) {
			PERROR("strdup");
			goto error;
		}
	}

error:
	return val;
}

/*
 * Force a read (imply TLS allocation for dlopen) of TLS variables.
 */
static
void lttng_ust_nest_count_alloc_tls(void)
{
	__asm__ __volatile__ ("" : : "m" (URCU_TLS(lttng_ust_nest_count)));
}

static
void lttng_ust_mutex_nest_alloc_tls(void)
{
	__asm__ __volatile__ ("" : : "m" (URCU_TLS(ust_mutex_nest)));
}

/*
 * Allocate lttng-ust urcu TLS.
 */
static
void lttng_ust_urcu_alloc_tls(void)
{
	(void) lttng_ust_urcu_read_ongoing();
}

void lttng_ust_common_init_thread(int flags)
{
	lttng_ust_urcu_alloc_tls();
	lttng_ringbuffer_alloc_tls();
	lttng_ust_vtid_init_thread(flags);
	lttng_ust_nest_count_alloc_tls();
	lttng_ust_procname_init_thread(flags);
	lttng_ust_mutex_nest_alloc_tls();
	lttng_ust_perf_counter_init_thread(flags);
	lttng_ust_common_alloc_tls();
	lttng_ust_cgroup_ns_init_thread(flags);
	lttng_ust_ipc_ns_init_thread(flags);
	lttng_ust_net_ns_init_thread(flags);
	lttng_ust_time_ns_init_thread(flags);
	lttng_ust_uts_ns_init_thread(flags);
	lttng_ust_ring_buffer_client_discard_alloc_tls();
	lttng_ust_ring_buffer_client_discard_rt_alloc_tls();
	lttng_ust_ring_buffer_client_overwrite_alloc_tls();
	lttng_ust_ring_buffer_client_overwrite_rt_alloc_tls();
	lttng_ust_ring_buffer_client_discard_per_channel_alloc_tls();
	lttng_ust_ring_buffer_client_discard_per_channel_rt_alloc_tls();
	lttng_ust_ring_buffer_client_overwrite_per_channel_alloc_tls();
	lttng_ust_ring_buffer_client_overwrite_per_channel_rt_alloc_tls();
}

/*
 * LTTng-UST uses Global Dynamic model TLS variables rather than IE
 * model because many versions of glibc don't preallocate a pool large
 * enough for TLS variables IE model defined in other shared libraries,
 * and causes issues when using LTTng-UST for Java tracing.
 *
 * Because of this use of Global Dynamic TLS variables, users wishing to
 * trace from signal handlers need to explicitly trigger the lazy
 * allocation of those variables for each thread before using them.
 * This can be triggered by calling lttng_ust_init_thread().
 */
void lttng_ust_init_thread(void)
{
	/*
	 * Because those TLS variables are global dynamic, we need to
	 * ensure those are initialized before a signal handler nesting over
	 * this thread attempts to use them.
	 */
	lttng_ust_common_init_thread(LTTNG_UST_INIT_THREAD_MASK);

	lttng_ust_urcu_register_thread();
}

int lttng_get_notify_socket(void *owner)
{
	struct sock_info *info = owner;

	return info->notify_socket;
}


char* lttng_ust_sockinfo_get_procname(void *owner)
{
	struct sock_info *info = owner;

	return info->procname;
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
int setup_ust_apps(void)
{
	char *ust_app_path = NULL;
	int ret = 0;
	uid_t uid;

	assert(!ust_app.wait_shm_mmap);

	uid = getuid();
	/*
	 * Disallow ust apps tracing for setuid binaries, because we
	 * cannot use the environment variables anyway.
	 */
	if (uid != geteuid()) {
		DBG("UST app tracing disabled for setuid binary.");
		assert(ust_app.allowed == 0);
		ret = 0;
		goto end;
	}
	ust_app_path = get_lttng_ust_app_path();
	if (!ust_app_path) {
		DBG("LTTNG_UST_APP_PATH environment variable not set.");
		assert(ust_app.allowed == 0);
		ret = -ENOENT;
		goto end;
	}
	/*
	 * The LTTNG_UST_APP_PATH env. var. disables global and local
	 * sessiond connections.
	 */
	ust_app.allowed = 1;
	snprintf(ust_app.sock_path, PATH_MAX, "%s/%s",
		ust_app_path, LTTNG_UST_SOCK_FILENAME);
	snprintf(ust_app.wait_shm_path, PATH_MAX, "%s/%s",
		ust_app_path,
		LTTNG_UST_WAIT_FILENAME);

	ust_app.wait_shm_mmap = get_map_shm(&ust_app);
	if (!ust_app.wait_shm_mmap) {
		WARN("Unable to get map shm for ust_app. Disabling LTTng-UST ust_app tracing.");
		ust_app.allowed = 0;
		ret = -EIO;
		goto end;
	}

	lttng_pthread_getname_np(ust_app.procname, LTTNG_UST_CONTEXT_PROCNAME_LEN);
end:
	if (ust_app_path)
		free(ust_app_path);
	return ret;
}

static
int setup_global_apps(void)
{
	int ret = 0;
	assert(!global_apps.wait_shm_mmap);

	/*
	 * The LTTNG_UST_APP_PATH env. var. disables global sessiond
	 * connections.
	 */
	if (ust_app.allowed)
		return 0;

	global_apps.wait_shm_mmap = get_map_shm(&global_apps);
	if (!global_apps.wait_shm_mmap) {
		WARN("Unable to get map shm for global apps. Disabling LTTng-UST global tracing.");
		global_apps.allowed = 0;
		ret = -EIO;
		goto error;
	}

	global_apps.allowed = 1;
	lttng_pthread_getname_np(global_apps.procname, LTTNG_UST_CONTEXT_PROCNAME_LEN);
error:
	return ret;
}

static
int setup_local_apps(void)
{
	int ret = 0;
	const char *home_dir;
	uid_t uid;

	assert(!local_apps.wait_shm_mmap);

	/*
	 * The LTTNG_UST_APP_PATH env. var. disables local sessiond
	 * connections.
	 */
	if (ust_app.allowed)
		return 0;

	uid = getuid();
	/*
	 * Disallow per-user tracing for setuid binaries.
	 */
	if (uid != geteuid()) {
		assert(local_apps.allowed == 0);
		ret = 0;
		goto end;
	}
	home_dir = get_lttng_home_dir();
	if (!home_dir) {
		WARN("HOME environment variable not set. Disabling LTTng-UST per-user tracing.");
		assert(local_apps.allowed == 0);
		ret = -ENOENT;
		goto end;
	}
	local_apps.allowed = 1;
	snprintf(local_apps.sock_path, PATH_MAX, "%s/%s/%s",
		home_dir,
		LTTNG_DEFAULT_HOME_RUNDIR,
		LTTNG_UST_SOCK_FILENAME);
	snprintf(local_apps.wait_shm_path, PATH_MAX, "/%s-%u",
		LTTNG_UST_WAIT_FILENAME,
		uid);

	local_apps.wait_shm_mmap = get_map_shm(&local_apps);
	if (!local_apps.wait_shm_mmap) {
		WARN("Unable to get map shm for local apps. Disabling LTTng-UST per-user tracing.");
		local_apps.allowed = 0;
		ret = -EIO;
		goto end;
	}

	lttng_pthread_getname_np(local_apps.procname, LTTNG_UST_CONTEXT_PROCNAME_LEN);
end:
	return ret;
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
		str_timeout = lttng_ust_getenv("LTTNG_UST_REGISTER_TIMEOUT");
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
		lttng_ust_getenv("LTTNG_UST_ALLOW_BLOCKING");

	if (str_allow_blocking) {
		DBG("%s environment variable is set",
			"LTTNG_UST_ALLOW_BLOCKING");
		lttng_ust_ringbuffer_set_allow_blocking();
	}
}

static
int register_to_sessiond(int socket, enum lttng_ust_ctl_socket_type type,
		const char *procname)
{
	return ustcomm_send_reg_msg(socket,
		type,
		CAA_BITS_PER_LONG,
		lttng_ust_rb_alignof(uint8_t) * CHAR_BIT,
		lttng_ust_rb_alignof(uint16_t) * CHAR_BIT,
		lttng_ust_rb_alignof(uint32_t) * CHAR_BIT,
		lttng_ust_rb_alignof(uint64_t) * CHAR_BIT,
		lttng_ust_rb_alignof(unsigned long) * CHAR_BIT,
		procname);
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
void decrement_sem_count(unsigned int count)
{
	int ret;

	assert(uatomic_read(&sem_count) >= count);

	if (uatomic_read(&sem_count) <= 0) {
		return;
	}

	ret = uatomic_add_return(&sem_count, -count);
	if (ret == 0) {
		ret = sem_post(&constructor_wait);
		assert(!ret);
	}
}

static
int handle_register_done(struct sock_info *sock_info)
{
	if (sock_info->registration_done)
		return 0;
	sock_info->registration_done = 1;

	decrement_sem_count(1);
	if (!sock_info->statedump_pending) {
		sock_info->initial_statedump_done = 1;
		decrement_sem_count(1);
	}

	return 0;
}

static
int handle_register_failed(struct sock_info *sock_info)
{
	if (sock_info->registration_done)
		return 0;
	sock_info->registration_done = 1;
	sock_info->initial_statedump_done = 1;

	decrement_sem_count(2);

	return 0;
}

/*
 * Only execute pending statedump after the constructor semaphore has
 * been posted by the current listener thread. This means statedump will
 * only be performed after the "registration done" command is received
 * from this thread's session daemon.
 *
 * This ensures we don't run into deadlock issues with the dynamic
 * loader mutex, which is held while the constructor is called and
 * waiting on the constructor semaphore. All operations requiring this
 * dynamic loader lock need to be postponed using this mechanism.
 *
 * In a scenario with two session daemons connected to the application,
 * it is possible that the first listener thread which receives the
 * registration done command issues its statedump while the dynamic
 * loader lock is still held by the application constructor waiting on
 * the semaphore. It will however be allowed to proceed when the
 * second session daemon sends the registration done command to the
 * second listener thread. This situation therefore does not produce
 * a deadlock.
 */
static
void handle_pending_statedump(struct sock_info *sock_info)
{
	if (sock_info->registration_done && sock_info->statedump_pending) {
		sock_info->statedump_pending = 0;
		pthread_mutex_lock(&ust_fork_mutex);
		lttng_handle_pending_statedump(sock_info);
		pthread_mutex_unlock(&ust_fork_mutex);

		if (!sock_info->initial_statedump_done) {
			sock_info->initial_statedump_done = 1;
			decrement_sem_count(1);
		}
	}
}

static inline
const char *bytecode_type_str(uint32_t cmd)
{
	switch (cmd) {
	case LTTNG_UST_ABI_CAPTURE:
		return "capture bytecode";
	case LTTNG_UST_ABI_FILTER:
		return "filter bytecode";
	default:
		abort();
	}
}

enum handle_message_error {
	MSG_OK = 0,
	MSG_ERROR = 1,
	MSG_SHUTDOWN = 2,
};

/*
 * Return:
 * < 0: error
 * 0: OK, handle command.
 * > 0: shutdown (no error).
 */
static
enum handle_message_error handle_error(struct sock_info *sock_info, ssize_t len,
		ssize_t expected_len, const char *str, int *error_code)
{
	if (!len) {
		/* orderly shutdown */
		*error_code = 0;
		return MSG_SHUTDOWN;
	}
	if (len == expected_len) {
		DBG("%s data received", str);
		*error_code = 0;
		return MSG_OK;
	}
	if (len < 0) {
		DBG("Receive failed from lttng-sessiond with errno %d", (int) -len);
		if (len == -ECONNRESET) {
			ERR("%s remote end closed connection", sock_info->name);
		}
		*error_code = len;
		return MSG_ERROR;
	}
	DBG("incorrect %s data message size: %zd", str, len);
	*error_code = -EINVAL;
	return MSG_ERROR;
}

static
int handle_bytecode_recv(struct sock_info *sock_info,
		int sock, struct ustcomm_ust_msg *lum)
{
	struct lttng_ust_bytecode_node *bytecode = NULL;
	enum lttng_ust_bytecode_type type;
	const struct lttng_ust_abi_objd_ops *ops;
	uint32_t data_size, data_size_max, reloc_offset;
	uint64_t seqnum;
	ssize_t len;
	int ret = 0;

	switch (lum->cmd) {
	case LTTNG_UST_ABI_FILTER:
		type = LTTNG_UST_BYTECODE_TYPE_FILTER;
		data_size = lum->u.filter.data_size;
		data_size_max = LTTNG_UST_ABI_FILTER_BYTECODE_MAX_LEN;
		reloc_offset = lum->u.filter.reloc_offset;
		seqnum = lum->u.filter.seqnum;
		break;
	case LTTNG_UST_ABI_CAPTURE:
		type = LTTNG_UST_BYTECODE_TYPE_CAPTURE;
		data_size = lum->u.capture.data_size;
		data_size_max = LTTNG_UST_ABI_CAPTURE_BYTECODE_MAX_LEN;
		reloc_offset = lum->u.capture.reloc_offset;
		seqnum = lum->u.capture.seqnum;
		break;
	default:
		abort();
	}

	if (data_size > data_size_max) {
		ERR("%s data size is too large: %u bytes",
				bytecode_type_str(lum->cmd), data_size);
		ret = -EINVAL;
		goto end;
	}

	if (reloc_offset > data_size) {
		ERR("%s reloc offset %u is not within data",
				bytecode_type_str(lum->cmd), reloc_offset);
		ret = -EINVAL;
		goto end;
	}

	/* Allocate the structure AND the `data[]` field. */
	bytecode = zmalloc(sizeof(*bytecode) + data_size);
	if (!bytecode) {
		ret = -ENOMEM;
		goto end;
	}

	bytecode->bc.len = data_size;
	bytecode->bc.reloc_offset = reloc_offset;
	bytecode->bc.seqnum = seqnum;
	bytecode->type = type;

	len = ustcomm_recv_unix_sock(sock, bytecode->bc.data, bytecode->bc.len);
	switch (handle_error(sock_info, len, bytecode->bc.len, bytecode_type_str(lum->cmd), &ret)) {
	case MSG_OK:
		break;
	case MSG_ERROR:		/* Fallthrough */
	case MSG_SHUTDOWN:
		goto end;
	}
	ops = lttng_ust_abi_objd_ops(lum->handle);
	if (!ops) {
		ret = -ENOENT;
		goto end;
	}

	if (ops->cmd)
		ret = ops->cmd(lum->handle, lum->cmd,
			(unsigned long) &bytecode,
			NULL, sock_info);
	else
		ret = -ENOSYS;

end:
	free(bytecode);
	return ret;
}

static
void prepare_cmd_reply(struct ustcomm_ust_reply *lur, uint32_t handle, uint32_t cmd, int ret)
{
	lur->handle = handle;
	lur->cmd = cmd;
	lur->ret_val = ret;
	if (ret >= 0) {
		lur->ret_code = LTTNG_UST_OK;
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
				lur->ret_code = -LTTNG_UST_ERR_EXIST;
				break;
			case -EINVAL:
				lur->ret_code = -LTTNG_UST_ERR_INVAL;
				break;
			case -ENOENT:
				lur->ret_code = -LTTNG_UST_ERR_NOENT;
				break;
			case -EPERM:
				lur->ret_code = -LTTNG_UST_ERR_PERM;
				break;
			case -ENOSYS:
				lur->ret_code = -LTTNG_UST_ERR_NOSYS;
				break;
			default:
				lur->ret_code = -LTTNG_UST_ERR;
				break;
			}
		} else {
			lur->ret_code = ret;
		}
	}
}

static
int handle_message(struct sock_info *sock_info,
		int sock, struct ustcomm_ust_msg *lum)
{
	int ret = 0;
	const struct lttng_ust_abi_objd_ops *ops;
	struct ustcomm_ust_reply lur = {};
	union lttng_ust_abi_args args;
	char ctxstr[LTTNG_UST_ABI_SYM_NAME_LEN];	/* App context string. */
	ssize_t len;
	void *var_len_cmd_data = NULL;

	if (ust_lock()) {
		ret = -LTTNG_UST_ERR_EXITING;
		goto error;
	}

	ops = lttng_ust_abi_objd_ops(lum->handle);
	if (!ops) {
		ret = -ENOENT;
		goto error;
	}

	switch (lum->cmd) {
	case LTTNG_UST_ABI_FILTER:
	case LTTNG_UST_ABI_EXCLUSION:
	case LTTNG_UST_ABI_CHANNEL:
	case LTTNG_UST_ABI_STREAM:
	case LTTNG_UST_ABI_CONTEXT:
		/*
		 * Those commands send additional payload after struct
		 * ustcomm_ust_msg, which makes it pretty much impossible to
		 * deal with "unknown command" errors without leaving the
		 * communication pipe in a out-of-sync state. This is part of
		 * the ABI between liblttng-ust-ctl and liblttng-ust, and
		 * should be fixed on the next breaking
		 * LTTNG_UST_ABI_MAJOR_VERSION protocol bump by indicating the
		 * total command message length as part of a message header so
		 * that the protocol can recover from invalid command errors.
		 */
		break;

	case LTTNG_UST_ABI_CAPTURE:
	case LTTNG_UST_ABI_COUNTER:
	case LTTNG_UST_ABI_COUNTER_CHANNEL:
	case LTTNG_UST_ABI_COUNTER_CPU:
#ifdef CONFIG_LTTNG_UST_EXPERIMENTAL_COUNTER
	case LTTNG_UST_ABI_COUNTER_EVENT:
#endif	/* CONFIG_LTTNG_UST_EXPERIMENTAL_COUNTER */
	case LTTNG_UST_ABI_EVENT_NOTIFIER_CREATE:
	case LTTNG_UST_ABI_EVENT_NOTIFIER_GROUP_CREATE:
		/*
		 * Those commands expect a reply to the struct ustcomm_ust_msg
		 * before sending additional payload.
		 */
		prepare_cmd_reply(&lur, lum->handle, lum->cmd, 0);

		ret = send_reply(sock, &lur);
		if (ret < 0) {
			DBG("error sending reply");
			goto error;
		}
		break;

	default:
		/*
		 * Other commands either don't send additional payload, or are
		 * unknown.
		 */
		break;
	}

	switch (lum->cmd) {
	case LTTNG_UST_ABI_REGISTER_DONE:
		if (lum->handle == LTTNG_UST_ABI_ROOT_HANDLE)
			ret = handle_register_done(sock_info);
		else
			ret = -EINVAL;
		break;
	case LTTNG_UST_ABI_RELEASE:
		if (lum->handle == LTTNG_UST_ABI_ROOT_HANDLE)
			ret = -EPERM;
		else
			ret = lttng_ust_abi_objd_unref(lum->handle, 1);
		break;
	case LTTNG_UST_ABI_CAPTURE:
	case LTTNG_UST_ABI_FILTER:
		ret = handle_bytecode_recv(sock_info, sock, lum);
		if (ret)
			goto error;
		break;
	case LTTNG_UST_ABI_EXCLUSION:
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
				count * LTTNG_UST_ABI_SYM_NAME_LEN);
		if (!node) {
			ret = -ENOMEM;
			goto error;
		}
		node->excluder.count = count;
		len = ustcomm_recv_unix_sock(sock, node->excluder.names,
				count * LTTNG_UST_ABI_SYM_NAME_LEN);
		switch (handle_error(sock_info, len, count * LTTNG_UST_ABI_SYM_NAME_LEN, "exclusion", &ret)) {
		case MSG_OK:
			break;
		case MSG_ERROR:		/* Fallthrough */
		case MSG_SHUTDOWN:
			free(node);
			goto error;
		}
		if (ops->cmd)
			ret = ops->cmd(lum->handle, lum->cmd,
					(unsigned long) &node,
					&args, sock_info);
		else
			ret = -ENOSYS;
		free(node);
		break;
	}
	case LTTNG_UST_ABI_EVENT_NOTIFIER_GROUP_CREATE:
	{
		int event_notifier_notif_fd, close_ret;

		len = ustcomm_recv_event_notifier_notif_fd_from_sessiond(sock,
			&event_notifier_notif_fd);
		switch (handle_error(sock_info, len, 1, "event notifier group", &ret)) {
		case MSG_OK:
			break;
		case MSG_ERROR:		/* Fallthrough */
		case MSG_SHUTDOWN:
			goto error;
		}
		args.event_notifier_handle.event_notifier_notif_fd = event_notifier_notif_fd;
		if (ops->cmd)
			ret = ops->cmd(lum->handle, lum->cmd,
					(unsigned long) &lum->u,
					&args, sock_info);
		else
			ret = -ENOSYS;
		if (args.event_notifier_handle.event_notifier_notif_fd >= 0) {
			lttng_ust_lock_fd_tracker();
			close_ret = close(args.event_notifier_handle.event_notifier_notif_fd);
			lttng_ust_unlock_fd_tracker();
			if (close_ret)
				PERROR("close");
		}
		break;
	}
	case LTTNG_UST_ABI_CHANNEL:
	{
		void *chan_data;
		int wakeup_fd;

		len = ustcomm_recv_channel_from_sessiond(sock,
				&chan_data, lum->u.channel.len,
				&wakeup_fd);
		switch (handle_error(sock_info, len, lum->u.channel.len, "channel", &ret)) {
		case MSG_OK:
			break;
		case MSG_ERROR:		/* Fallthrough */
		case MSG_SHUTDOWN:
			goto error;
		}
		args.channel.chan_data = chan_data;
		args.channel.wakeup_fd = wakeup_fd;
		if (ops->cmd)
			ret = ops->cmd(lum->handle, lum->cmd,
					(unsigned long) &lum->u,
					&args, sock_info);
		else
			ret = -ENOSYS;
		if (args.channel.wakeup_fd >= 0) {
			int close_ret;

			lttng_ust_lock_fd_tracker();
			close_ret = close(args.channel.wakeup_fd);
			lttng_ust_unlock_fd_tracker();
			args.channel.wakeup_fd = -1;
			if (close_ret)
				PERROR("close");
		}
		free(args.channel.chan_data);
		break;
	}
	case LTTNG_UST_ABI_STREAM:
	{
		int close_ret;

		/* Receive shm_fd, wakeup_fd */
		ret = ustcomm_recv_stream_from_sessiond(sock,
			NULL,
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
		if (args.stream.shm_fd >= 0) {
			lttng_ust_lock_fd_tracker();
			close_ret = close(args.stream.shm_fd);
			lttng_ust_unlock_fd_tracker();
			args.stream.shm_fd = -1;
			if (close_ret)
				PERROR("close");
		}
		if (args.stream.wakeup_fd >= 0) {
			lttng_ust_lock_fd_tracker();
			close_ret = close(args.stream.wakeup_fd);
			lttng_ust_unlock_fd_tracker();
			args.stream.wakeup_fd = -1;
			if (close_ret)
				PERROR("close");
		}
		break;
	}
	case LTTNG_UST_ABI_CONTEXT:
		switch (lum->u.context.ctx) {
		case LTTNG_UST_ABI_CONTEXT_APP_CONTEXT:
		{
			char *p;
			size_t ctxlen, recvlen;

			ctxlen = strlen("$app.") + lum->u.context.u.app_ctx.provider_name_len - 1
					+ strlen(":") + lum->u.context.u.app_ctx.ctx_name_len;
			if (ctxlen >= LTTNG_UST_ABI_SYM_NAME_LEN) {
				ERR("Application context string length size is too large: %zu bytes",
					ctxlen);
				ret = -EINVAL;
				goto error;
			}
			strcpy(ctxstr, "$app.");
			p = &ctxstr[strlen("$app.")];
			recvlen = ctxlen - strlen("$app.");
			len = ustcomm_recv_unix_sock(sock, p, recvlen);
			switch (handle_error(sock_info, len, recvlen, "app context", &ret)) {
			case MSG_OK:
				break;
			case MSG_ERROR:		/* Fallthrough */
			case MSG_SHUTDOWN:
				goto error;
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
	case LTTNG_UST_ABI_COUNTER:
	{
		len = ustcomm_recv_var_len_cmd_from_sessiond(sock,
				&var_len_cmd_data, lum->u.var_len_cmd.cmd_len);
		switch (handle_error(sock_info, len, lum->u.var_len_cmd.cmd_len, "counter", &ret)) {
		case MSG_OK:
			break;
		case MSG_ERROR:		/* Fallthrough */
		case MSG_SHUTDOWN:
			goto error;
		}
		args.counter.len = lum->u.var_len_cmd.cmd_len;
		if (ops->cmd)
			ret = ops->cmd(lum->handle, lum->cmd,
					(unsigned long) var_len_cmd_data,
					&args, sock_info);
		else
			ret = -ENOSYS;
		break;
	}
	case LTTNG_UST_ABI_COUNTER_CHANNEL:
	{
		len = ustcomm_recv_var_len_cmd_from_sessiond(sock,
				&var_len_cmd_data, lum->u.var_len_cmd.cmd_len);
		switch (handle_error(sock_info, len, lum->u.var_len_cmd.cmd_len, "counter channel", &ret)) {
		case MSG_OK:
			break;
		case MSG_ERROR:		/* Fallthrough */
		case MSG_SHUTDOWN:
			goto error;
		}
		/* Receive shm_fd */
		ret = ustcomm_recv_counter_shm_from_sessiond(sock, &args.counter_shm.shm_fd);
		if (ret) {
			goto error;
		}
		args.counter_shm.len = lum->u.var_len_cmd.cmd_len;
		if (ops->cmd)
			ret = ops->cmd(lum->handle, lum->cmd,
					(unsigned long) var_len_cmd_data,
					&args, sock_info);
		else
			ret = -ENOSYS;
		if (args.counter_shm.shm_fd >= 0) {
			int close_ret;

			lttng_ust_lock_fd_tracker();
			close_ret = close(args.counter_shm.shm_fd);
			lttng_ust_unlock_fd_tracker();
			args.counter_shm.shm_fd = -1;
			if (close_ret)
				PERROR("close");
		}
		break;
	}
	case LTTNG_UST_ABI_COUNTER_CPU:
	{
		len = ustcomm_recv_var_len_cmd_from_sessiond(sock,
				&var_len_cmd_data, lum->u.var_len_cmd.cmd_len);
		switch (handle_error(sock_info, len, lum->u.var_len_cmd.cmd_len, "counter cpu", &ret)) {
		case MSG_OK:
			break;
		case MSG_ERROR:		/* Fallthrough */
		case MSG_SHUTDOWN:
			goto error;
		}
		/* Receive shm_fd */
		ret = ustcomm_recv_counter_shm_from_sessiond(sock, &args.counter_shm.shm_fd);
		if (ret) {
			goto error;
		}
		args.counter_shm.len = lum->u.var_len_cmd.cmd_len;
		if (ops->cmd)
			ret = ops->cmd(lum->handle, lum->cmd,
					(unsigned long) var_len_cmd_data,
					&args, sock_info);
		else
			ret = -ENOSYS;
		if (args.counter_shm.shm_fd >= 0) {
			int close_ret;

			lttng_ust_lock_fd_tracker();
			close_ret = close(args.counter_shm.shm_fd);
			lttng_ust_unlock_fd_tracker();
			args.counter_shm.shm_fd = -1;
			if (close_ret)
				PERROR("close");
		}
		break;
	}
#ifdef CONFIG_LTTNG_UST_EXPERIMENTAL_COUNTER
	case LTTNG_UST_ABI_COUNTER_EVENT:
	{
		len = ustcomm_recv_var_len_cmd_from_sessiond(sock,
				&var_len_cmd_data, lum->u.var_len_cmd.cmd_len);
		switch (handle_error(sock_info, len, lum->u.var_len_cmd.cmd_len, "counter event", &ret)) {
		case MSG_OK:
			break;
		case MSG_ERROR:		/* Fallthrough */
		case MSG_SHUTDOWN:
			goto error;
		}
		args.counter_event.len = lum->u.var_len_cmd.cmd_len;
		if (ops->cmd)
			ret = ops->cmd(lum->handle, lum->cmd,
					(unsigned long) var_len_cmd_data,
					&args, sock_info);
		else
			ret = -ENOSYS;
		break;
	}
#endif	/* CONFIG_LTTNG_UST_EXPERIMENTAL_COUNTER */
	case LTTNG_UST_ABI_EVENT_NOTIFIER_CREATE:
	{
		len = ustcomm_recv_var_len_cmd_from_sessiond(sock,
				&var_len_cmd_data, lum->u.var_len_cmd.cmd_len);
		switch (handle_error(sock_info, len, lum->u.var_len_cmd.cmd_len, "event notifier", &ret)) {
		case MSG_OK:
			break;
		case MSG_ERROR:		/* Fallthrough */
		case MSG_SHUTDOWN:
			goto error;
		}
		args.event_notifier.len = lum->u.var_len_cmd.cmd_len;
		if (ops->cmd)
			ret = ops->cmd(lum->handle, lum->cmd,
					(unsigned long) var_len_cmd_data,
					&args, sock_info);
		else
			ret = -ENOSYS;
		break;
	}

	default:
		if (ops->cmd)
			ret = ops->cmd(lum->handle, lum->cmd,
					(unsigned long) &lum->u,
					&args, sock_info);
		else
			ret = -ENOSYS;
		break;
	}

	prepare_cmd_reply(&lur, lum->handle, lum->cmd, ret);

	if (ret >= 0) {
		switch (lum->cmd) {
		case LTTNG_UST_ABI_TRACER_VERSION:
			lur.u.version = lum->u.version;
			break;
		case LTTNG_UST_ABI_TRACEPOINT_LIST_GET:
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
		case LTTNG_UST_ABI_TRACEPOINT_FIELD_LIST_GET:
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

	free(var_len_cmd_data);
	return ret;
}

static
void cleanup_sock_info(struct sock_info *sock_info, int exiting)
{
	int ret;

	if (sock_info->root_handle != -1) {
		ret = lttng_ust_abi_objd_unref(sock_info->root_handle, 1);
		if (ret) {
			ERR("Error unref root handle");
		}
		sock_info->root_handle = -1;
	}


	/*
	 * wait_shm_mmap, socket and notify socket are used by listener
	 * threads outside of the ust lock, so we cannot tear them down
	 * ourselves, because we cannot join on these threads. Leave
	 * responsibility of cleaning up these resources to the OS
	 * process exit.
	 */
	if (exiting)
		return;

	sock_info->registration_done = 0;
	sock_info->initial_statedump_done = 0;

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

		page_size = LTTNG_UST_PAGE_SIZE;
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

static
int wait_shm_open(struct sock_info *sock_info, int flags, mode_t mode)
{
	if (sock_info->wait_shm_is_file)
		return open(sock_info->wait_shm_path, flags, mode);
	else
		return shm_open(sock_info->wait_shm_path, flags, mode);
}

/*
 * Using fork to set umask in the child process (not multi-thread safe).
 * We deal with the shm_open vs ftruncate race (happening when the
 * sessiond owns the shm and does not let everybody modify it, to ensure
 * safety against shm_unlink) by simply letting the mmap fail and
 * retrying after a few seconds.
 * For channel shm, everybody has rw access to it until the sessiond
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
	wait_shm_fd = wait_shm_open(sock_info, O_RDONLY, 0);
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
		int status, wait_ret;

		/*
		 * Parent: wait for child to return, in which case the
		 * shared memory map will have been created.
		 */
		wait_ret = waitpid(pid, &status, 0);
		if (wait_ret < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
			wait_shm_fd = -1;
			goto end;
		}
		/*
		 * Try to open read-only again after creation.
		 */
		wait_shm_fd = wait_shm_open(sock_info, O_RDONLY, 0);
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
		if (sock_info->multi_user)
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
		wait_shm_fd = wait_shm_open(sock_info,
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
		 * able to wake us up. For channel shm, we open it even
		 * if rw access is not granted, because the root.root
		 * sessiond will be able to override all rights and wake
		 * us up.
		 */
		if (!sock_info->multi_user && errno != EACCES) {
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
	if (wait_shm_fd >= 0 && !sock_info->multi_user) {
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

	ret = lttng_ust_add_fd_to_tracker(wait_shm_fd);
	if (ret < 0) {
		ret = close(wait_shm_fd);
		if (!ret) {
			PERROR("Error closing fd");
		}
		lttng_ust_unlock_fd_tracker();
		goto error;
	}

	wait_shm_fd = ret;
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
	/* Use ust_lock to check if we should quit. */
	if (ust_lock()) {
		goto quit;
	}
	if (wait_poll_fallback) {
		goto error;
	}
	ust_unlock();

	assert(sock_info->wait_shm_mmap);

	DBG("Waiting for %s apps sessiond", sock_info->name);
	/* Wait for futex wakeup */
	while (!uatomic_read((int32_t *) sock_info->wait_shm_mmap)) {
		if (!lttng_ust_futex_async((int32_t *) sock_info->wait_shm_mmap, FUTEX_WAIT, 0, NULL, NULL, 0)) {
			/*
			 * Prior queued wakeups queued by unrelated code
			 * using the same address can cause futex wait to
			 * return 0 even through the futex value is still
			 * 0 (spurious wakeups). Check the value again
			 * in user-space to validate whether it really
			 * differs from 0.
			 */
			continue;
		}
		switch (errno) {
		case EAGAIN:
			/* Value already changed. */
			goto end_wait;
		case EINTR:
			/* Retry if interrupted by signal. */
			break;	/* Get out of switch. Check again. */
		case EFAULT:
			wait_poll_fallback = 1;
			DBG(
"Linux kernels 2.6.33 to 3.0 (with the exception of stable versions) "
"do not support FUTEX_WAKE on read-only memory mappings correctly. "
"Please upgrade your kernel "
"(fix is commit 9ea71503a8ed9184d2d0b8ccc4d269d05f7940ae in Linux kernel "
"mainline). LTTng-UST will use polling mode fallback.");
			if (lttng_ust_logging_debug_enabled())
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
	int sock, ret, prev_connect_failed = 0, has_waited = 0, fd;
	long timeout;

	lttng_ust_common_init_thread(0);
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

	if (ust_lock()) {
		goto quit;
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
		ret = handle_register_failed(sock_info);
		assert(!ret);
		ust_unlock();
		goto restart;
	}
	fd = ret;
	ret = lttng_ust_add_fd_to_tracker(fd);
	if (ret < 0) {
		ret = close(fd);
		if (ret) {
			PERROR("close on sock_info->socket");
		}
		ret = -1;
		lttng_ust_unlock_fd_tracker();
		ust_unlock();
		goto quit;
	}

	sock_info->socket = ret;
	lttng_ust_unlock_fd_tracker();

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

	ret = register_to_sessiond(sock_info->socket, LTTNG_UST_CTL_SOCKET_CMD,
		sock_info->procname);
	if (ret < 0) {
		ERR("Error registering to %s ust cmd socket",
			sock_info->name);
		prev_connect_failed = 1;
		/*
		 * If we cannot register to the sessiond daemon, don't
		 * delay constructor execution.
		 */
		ret = handle_register_failed(sock_info);
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
		ret = handle_register_failed(sock_info);
		assert(!ret);
		ust_unlock();
		goto restart;
	}

	fd = ret;
	ret = lttng_ust_add_fd_to_tracker(fd);
	if (ret < 0) {
		ret = close(fd);
		if (ret) {
			PERROR("close on sock_info->notify_socket");
		}
		ret = -1;
		lttng_ust_unlock_fd_tracker();
		ust_unlock();
		goto quit;
	}

	sock_info->notify_socket = ret;
	lttng_ust_unlock_fd_tracker();

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
			LTTNG_UST_CTL_SOCKET_NOTIFY, sock_info->procname);
	if (ret < 0) {
		ERR("Error registering to %s ust notify socket",
			sock_info->name);
		prev_connect_failed = 1;
		/*
		 * If we cannot register to the sessiond daemon, don't
		 * delay constructor execution.
		 */
		ret = handle_register_failed(sock_info);
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
			ret = handle_register_failed(sock_info);
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
	lttng_ust_abi_objd_table_owner_cleanup(sock_info);
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
void lttng_ust_libc_wrapper_malloc_ctor(void)
{
}

/*
 * Use a symbol of the previous ABI to detect if liblttng-ust.so.0 is loaded in
 * the current process.
 */
#define LTTNG_UST_SONAME_0_SYM	"ltt_probe_register"

static
void lttng_ust_check_soname_0(void)
{
	if (!dlsym(RTLD_DEFAULT, LTTNG_UST_SONAME_0_SYM))
		return;

	CRIT("Incompatible library ABIs detected within the same process. "
		"The process is likely linked against different major soname of LTTng-UST which is unsupported. "
		"The detection was triggered by lookup of ABI 0 symbol \"%s\" in the Global Symbol Table\n",
		LTTNG_UST_SONAME_0_SYM);
}

/*
 * Expose a canary symbol of the previous ABI to ensure we catch uses of a
 * liblttng-ust.so.0 dlopen'd after .so.1 has been loaded. Use a different
 * symbol than the detection code to ensure we don't detect ourself.
 *
 * This scheme will only work on systems where the global symbol table has
 * priority when resolving the symbols of a dlopened shared object, which is
 * the case on Linux but not on FreeBSD.
 */
void init_usterr(void);
void init_usterr(void)
{
	CRIT("Incompatible library ABIs detected within the same process. "
		"The process is likely linked against different major soname of LTTng-UST which is unsupported. "
		"The detection was triggered by canary symbol \"%s\"\n", __func__);
}

/*
 * sessiond monitoring thread: monitor presence of global and per-user
 * sessiond by polling the application common named pipe.
 */
static
void lttng_ust_ctor(void)
	__attribute__((constructor));
static
void lttng_ust_ctor(void)
{
	struct timespec constructor_timeout;
	sigset_t sig_all_blocked, orig_parent_mask;
	pthread_attr_t thread_attr;
	int timeout_mode;
	int ret;
	void *handle;

	if (uatomic_xchg(&initialized, 1) == 1)
		return;

	/*
	 * Fixup interdependency between TLS allocation mutex (which happens
	 * to be the dynamic linker mutex) and ust_lock, taken within
	 * the ust lock.
	 */
	lttng_ust_common_init_thread(0);

	lttng_ust_loaded = 1;

	/*
	 * Check if we find a symbol of the previous ABI in the current process
	 * as different ABIs of liblttng-ust can't co-exist in a process. If we
	 * do so, emit a critical log message which will also abort if the
	 * LTTNG_UST_ABORT_ON_CRITICAL environment variable is set.
	 */
	lttng_ust_check_soname_0();

	/*
	 * We need to ensure that the liblttng-ust library is not unloaded to avoid
	 * the unloading of code used by the ust_listener_threads as we can not
	 * reliably know when they exited. To do that, manually load
	 * liblttng-ust.so to increment the dynamic loader's internal refcount for
	 * this library so it never becomes zero, thus never gets unloaded from the
	 * address space of the process. Since we are already running in the
	 * constructor of the LTTNG_UST_LIB_SONAME library, calling dlopen will
	 * simply increment the refcount and no additional work is needed by the
	 * dynamic loader as the shared library is already loaded in the address
	 * space. As a safe guard, we use the RTLD_NODELETE flag to prevent
	 * unloading of the UST library if its refcount becomes zero (which should
	 * never happen). Do the return value check but discard the handle at the
	 * end of the function as it's not needed.
	 */
	handle = dlopen(LTTNG_UST_LIB_SONAME, RTLD_LAZY | RTLD_NODELETE);
	if (!handle) {
		ERR("dlopen of liblttng-ust shared library (%s).", LTTNG_UST_LIB_SONAME);
	} else {
		DBG("dlopened liblttng-ust shared library (%s).", LTTNG_UST_LIB_SONAME);
	}

	/*
	 * We want precise control over the order in which we construct
	 * our sub-libraries vs starting to receive commands from
	 * sessiond (otherwise leading to errors when trying to create
	 * sessiond before the init functions are completed).
	 */

	/*
	 * Both the logging and getenv lazy-initialization uses getenv()
	 * internally and thus needs to be explicitly initialized in
	 * liblttng-ust before we start any threads as an unsuspecting normally
	 * single threaded application using liblttng-ust could be using
	 * setenv() which is not thread-safe.
	 */
	lttng_ust_logging_init();
	lttng_ust_getenv_init();

	/* Call the liblttng-ust-common constructor. */
	lttng_ust_common_ctor();

	lttng_ust_tp_init();
	lttng_ust_statedump_init();
	lttng_ust_ring_buffer_clients_init();
	lttng_ust_counter_clients_init();
	lttng_perf_counter_init();
	/*
	 * Invoke ust malloc wrapper init before starting other threads.
	 */
	lttng_ust_libc_wrapper_malloc_ctor();

	timeout_mode = get_constructor_timeout(&constructor_timeout);

	get_allow_blocking();

	ret = sem_init(&constructor_wait, 0, 0);
	if (ret) {
		PERROR("sem_init");
	}

	ret = setup_ust_apps();
	if (ret) {
		assert(ust_app.allowed == 0);
		DBG("ust_app setup returned %d", ret);
	}
	ret = setup_global_apps();
	if (ret) {
		assert(global_apps.allowed == 0);
		DBG("global apps setup returned %d", ret);
	}

	ret = setup_local_apps();
	if (ret) {
		assert(local_apps.allowed == 0);
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

	if (ust_app.allowed) {
		pthread_mutex_lock(&ust_exit_mutex);
		ret = pthread_create(&ust_app.ust_listener, &thread_attr,
				ust_listener_thread, &ust_app);
		if (ret) {
			ERR("pthread_create ust_app: %s", strerror(ret));
		}
		ust_app.thread_active = 1;
		pthread_mutex_unlock(&ust_exit_mutex);
	} else {
		handle_register_done(&ust_app);
	}

	if (global_apps.allowed) {
		pthread_mutex_lock(&ust_exit_mutex);
		ret = pthread_create(&global_apps.ust_listener, &thread_attr,
				ust_listener_thread, &global_apps);
		if (ret) {
			ERR("pthread_create global: %s", strerror(ret));
		}
		global_apps.thread_active = 1;
		pthread_mutex_unlock(&ust_exit_mutex);
	} else {
		handle_register_done(&global_apps);
	}

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
	cleanup_sock_info(&ust_app, exiting);
	cleanup_sock_info(&global_apps, exiting);
	cleanup_sock_info(&local_apps, exiting);
	ust_app.allowed = 0;
	local_apps.allowed = 0;
	global_apps.allowed = 0;
	/*
	 * The teardown in this function all affect data structures
	 * accessed under the UST lock by the listener thread. This
	 * lock, along with the lttng_ust_comm_should_quit flag, ensure
	 * that none of these threads are accessing this data at this
	 * point.
	 */
	lttng_ust_abi_exit();
	lttng_ust_abi_events_exit();
	lttng_perf_counter_exit();
	lttng_ust_ring_buffer_clients_exit();
	lttng_ust_counter_clients_exit();
	lttng_ust_statedump_destroy();
	lttng_ust_tp_exit();
	if (!exiting) {
		/* Reinitialize values for fork */
		sem_count = sem_count_initial_value;
		lttng_ust_comm_should_quit = 0;
		initialized = 0;
	}
}

static
void lttng_ust_exit(void)
	__attribute__((destructor));
static
void lttng_ust_exit(void)
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
	if (ust_app.thread_active) {
		ret = pthread_cancel(ust_app.ust_listener);
		if (ret) {
			ERR("Error cancelling ust listener thread: %s",
				strerror(ret));
		} else {
			ust_app.thread_active = 0;
		}
	}
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

static
void ust_context_ns_reset(void)
{
	lttng_context_pid_ns_reset();
	lttng_context_cgroup_ns_reset();
	lttng_context_ipc_ns_reset();
	lttng_context_mnt_ns_reset();
	lttng_context_net_ns_reset();
	lttng_context_user_ns_reset();
	lttng_context_time_ns_reset();
	lttng_context_uts_ns_reset();
}

static
void ust_context_vuids_reset(void)
{
	lttng_context_vuid_reset();
	lttng_context_veuid_reset();
	lttng_context_vsuid_reset();
}

static
void ust_context_vgids_reset(void)
{
	lttng_context_vgid_reset();
	lttng_context_vegid_reset();
	lttng_context_vsgid_reset();
}

/*
 * We exclude the worker threads across fork and clone (except
 * CLONE_VM), because these system calls only keep the forking thread
 * running in the child.  Therefore, we don't want to call fork or clone
 * in the middle of an tracepoint or ust tracing state modification.
 * Holding this mutex protects these structures across fork and clone.
 */
void lttng_ust_before_fork(sigset_t *save_sigset)
{
	/*
	 * Disable signals. This is to avoid that the child intervenes
	 * before it is properly setup for tracing. It is safer to
	 * disable all signals, because then we know we are not breaking
	 * anything by restoring the original mask.
         */
	sigset_t all_sigs;
	int ret;

	/* Allocate lttng-ust TLS. */
	lttng_ust_common_init_thread(0);

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
	lttng_ust_urcu_before_fork();
	lttng_ust_lock_fd_tracker();
	lttng_perf_lock();
}

static void ust_after_fork_common(sigset_t *restore_sigset)
{
	int ret;

	DBG("process %d", getpid());
	lttng_perf_unlock();
	lttng_ust_unlock_fd_tracker();
	ust_unlock();

	pthread_mutex_unlock(&ust_fork_mutex);

	/* Restore signals */
	ret = sigprocmask(SIG_SETMASK, restore_sigset, NULL);
	if (ret == -1) {
		PERROR("sigprocmask");
	}
}

void lttng_ust_after_fork_parent(sigset_t *restore_sigset)
{
	if (URCU_TLS(lttng_ust_nest_count))
		return;
	DBG("process %d", getpid());
	lttng_ust_urcu_after_fork_parent();
	/* Release mutexes and re-enable signals */
	ust_after_fork_common(restore_sigset);
}

/*
 * After fork, in the child, we need to cleanup all the leftover state,
 * except the worker thread which already magically disappeared thanks
 * to the weird Linux fork semantics. After tyding up, we call
 * lttng_ust_ctor() again to start over as a new PID.
 *
 * This is meant for forks() that have tracing in the child between the
 * fork and following exec call (if there is any).
 */
void lttng_ust_after_fork_child(sigset_t *restore_sigset)
{
	if (URCU_TLS(lttng_ust_nest_count))
		return;
	lttng_context_vpid_reset();
	lttng_context_vtid_reset();
	lttng_ust_context_procname_reset();
	ust_context_ns_reset();
	ust_context_vuids_reset();
	ust_context_vgids_reset();
	DBG("process %d", getpid());
	/* Release urcu mutexes */
	lttng_ust_urcu_after_fork_child();
	lttng_ust_cleanup(0);
	/* Release mutexes and re-enable signals */
	ust_after_fork_common(restore_sigset);
	lttng_ust_ctor();
}

void lttng_ust_after_setns(void)
{
	ust_context_ns_reset();
	ust_context_vuids_reset();
	ust_context_vgids_reset();
}

void lttng_ust_after_unshare(void)
{
	ust_context_ns_reset();
	ust_context_vuids_reset();
	ust_context_vgids_reset();
}

void lttng_ust_after_setuid(void)
{
	ust_context_vuids_reset();
}

void lttng_ust_after_seteuid(void)
{
	ust_context_vuids_reset();
}

void lttng_ust_after_setreuid(void)
{
	ust_context_vuids_reset();
}

void lttng_ust_after_setresuid(void)
{
	ust_context_vuids_reset();
}

void lttng_ust_after_setgid(void)
{
	ust_context_vgids_reset();
}

void lttng_ust_after_setegid(void)
{
	ust_context_vgids_reset();
}

void lttng_ust_after_setregid(void)
{
	ust_context_vgids_reset();
}

void lttng_ust_after_setresgid(void)
{
	ust_context_vgids_reset();
}

void lttng_ust_sockinfo_session_enabled(void *owner)
{
	struct sock_info *sock_info = owner;
	sock_info->statedump_pending = 1;
}
