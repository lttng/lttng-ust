/*
 * ust-basic-tracing.c - Basic single-session, single-channel, single-process UST tracing
 *
 * Copyright (C) 2011 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License only.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <limits.h>
#include <urcu/futex.h>
#include <urcu/uatomic.h>
#include <assert.h>
#include <sys/socket.h>

#include <ust-comm.h>
#include <lttng/ust-error.h>
#include "../../libringbuffer/backend.h"
#include "../../libringbuffer/frontend.h"
#include "../../liblttng-ust/compat.h"	/* For ENODATA */

#define MAX_NR_STREAMS	64
#define MAX_NR_EVENTS	128

static int session_handle;
static struct lttng_ust_object_data metadata_stream_data;
static struct lttng_ust_object_data metadata_data;
static struct lttng_ust_object_data channel_data;
static struct lttng_ust_object_data stream_data[MAX_NR_STREAMS];
static int event_handle[MAX_NR_EVENTS];
static int context_handle;

static int apps_socket = -1;
static char apps_sock_path[PATH_MAX];
static char local_apps_wait_shm_path[PATH_MAX];

static volatile int quit_program;

static void handle_signals(int signo)
{
	quit_program = 1;
}

static
int open_streams(int sock, int channel_handle, struct lttng_ust_object_data *stream_datas,
		int nr_check)
{
	int ret, k = 0;

	for (;;) {
		struct ustcomm_ust_msg lum;
		struct ustcomm_ust_reply lur;

		memset(&lum, 0, sizeof(lum));
		lum.handle = channel_handle;
		lum.cmd = LTTNG_UST_STREAM;
		ret = ustcomm_send_app_cmd(sock, &lum, &lur);
		if (!ret) {
			assert(k < nr_check);
			stream_datas[k].handle = lur.ret_val;
			printf("received stream handle %u\n",
				stream_datas[k].handle);
			if (lur.ret_code == LTTNG_UST_OK) {
				ssize_t len;

				stream_datas[k].memory_map_size = lur.u.stream.memory_map_size;
				/* get shm fd */
				len = ustcomm_recv_fd(sock);
				if (len < 0)
					return -EINVAL;
				stream_datas[k].shm_fd = len;
				/* get wait fd */
				len = ustcomm_recv_fd(sock);
				if (len < 0)
					return -EINVAL;
				stream_datas[k].wait_fd = len;
			}
			k++;
		}
		if (ret == -LTTNG_UST_ERR_NOENT)
			break;
		if (ret)
			return ret;
	}
	return 0;
}

static
int close_streams(int sock, struct lttng_ust_object_data *stream_datas, int nr_check)
{
	int ret, k;

	for (k = 0; k < nr_check; k++) {
		struct ustcomm_ust_msg lum;
		struct ustcomm_ust_reply lur;

		if (!stream_datas[k].handle)
			continue;
		memset(&lum, 0, sizeof(lum));
		lum.handle = stream_datas[k].handle;
		lum.cmd = LTTNG_UST_RELEASE;
		ret = ustcomm_send_app_cmd(sock, &lum, &lur);
		if (ret) {
			printf("Error closing stream\n");
			return ret;
		}
		if (stream_datas[k].shm_fd >= 0) {
			ret = close(stream_datas[k].shm_fd);
			if (ret) {
				printf("Error closing stream shm_fd\n");
				return ret;
			}
		}
		if (stream_datas[k].wait_fd >= 0) {
			ret = close(stream_datas[k].wait_fd);
			if (ret) {
				printf("Error closing stream wait_fd\n");
				return ret;
			}
		}
	}
	return 0;
}

static
struct lttng_ust_shm_handle *map_channel(struct lttng_ust_object_data *chan_data,
		struct lttng_ust_object_data *stream_datas, int nr_check)
{
	struct lttng_ust_shm_handle *handle;
	struct channel *chan;
	int k, ret;

	/* map metadata channel */
	handle = channel_handle_create(chan_data->shm_fd,
		chan_data->wait_fd,
		chan_data->memory_map_size);
	if (!handle) {
		printf("create handle error\n");
		return NULL;
	}
	chan_data->shm_fd = -1;
	chan_data->wait_fd = -1;
	chan = shmp(handle, handle->chan);

	for (k = 0; k < nr_check; k++) {
		struct lttng_ust_object_data *stream_data = &stream_datas[k];

		if (!stream_data->handle)
			break;
		/* map stream */
		ret = channel_handle_add_stream(handle,
			stream_data->shm_fd,
			stream_data->wait_fd,
			stream_data->memory_map_size);
		if (ret) {
			printf("add stream error\n");
			goto error_destroy;
		}
		stream_data->shm_fd = -1;
		stream_data->wait_fd = -1;
	}
	return handle;

error_destroy:
	channel_destroy(chan, handle, 1);
	return NULL;
}

static
void unmap_channel(struct lttng_ust_shm_handle *handle)
{
	struct channel *chan;

	chan = shmp(handle, handle->chan);
	/* unmap channel */
	channel_destroy(chan, handle, 1);
}

static
int consume_stream(struct lttng_ust_shm_handle *handle, int cpu, char *outfile)
{
	struct channel *chan;
	struct lttng_ust_lib_ring_buffer *buf;
	int outfd, ret;
	int *shm_fd, *wait_fd;
	uint64_t *memory_map_size;

	chan = shmp(handle, handle->chan);

	/* open stream */
	buf = channel_get_ring_buffer(&chan->backend.config,
		chan, cpu, handle, &shm_fd, &wait_fd, &memory_map_size);
	if (!buf)
		return -ENOENT;
	ret = lib_ring_buffer_open_read(buf, handle, 1);
	if (ret) {
		return -1;
	}

	/* copy */
	outfd = open(outfile, O_WRONLY | O_CREAT | O_TRUNC,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (outfd < 0) {
		perror("open output");
		return -1;
	}

	printf("Waiting for buffer data for %s\n", outfile);
	for (;;) {
		unsigned long read_size;
		unsigned long copy_size;
		char *ptr;

		ret = lib_ring_buffer_get_next_subbuf(buf, handle);
		printf("get next ret %d\n", ret);
		if (ret == -ENODATA)
			break;
		if (ret == -EAGAIN) {
			sleep(1);
			continue;
		}
		if (ret) {
			printf("Error %d in lib_ring_buffer_get_next_subbuf\n", ret);
			return -1;
		}
		read_size = lib_ring_buffer_get_read_data_size(
			&chan->backend.config, buf, handle);
		read_size = PAGE_ALIGN(read_size);
		ptr = lib_ring_buffer_read_offset_address(
			&buf->backend, 0, handle);
		printf("WRITE: copy %lu bytes\n", read_size);
		copy_size = write(outfd, ptr, read_size);
		if (copy_size < read_size) {
			printf("write issue: copied %lu, expected %lu\n", copy_size, read_size);
		}
		lib_ring_buffer_put_next_subbuf(buf, handle);
	}

	ret = close(outfd);
	if (ret) {
		perror("close");
		return -1;
	}

	/* close stream */
	lib_ring_buffer_release_read(buf, handle, 1);
	return 0;
}

static
int consume_buffers(const char *outputpath)
{
	int k, ret;
	mode_t old_umask;
	char pathname[PATH_MAX];
	struct lttng_ust_shm_handle *handle;

	snprintf(pathname, PATH_MAX - 1, "%s", outputpath);
	old_umask = umask(0);
	ret = mkdir(pathname, S_IRWXU | S_IRWXG);
	if (ret && errno != EEXIST) {
		perror("mkdir");
		umask(old_umask);
		return -1;
	}
	umask(old_umask);

	/* copy metadata */
	handle = map_channel(&metadata_data,
			&metadata_stream_data, 1);
	if (!handle)
		return -1;
	snprintf(pathname, PATH_MAX - 1,
		"%s/metadata", outputpath);
	ret = consume_stream(handle, -1, pathname);
	if (ret && ret != -ENOENT) {
		printf("Error in consume_stream\n");
		return ret;
	}
	unmap_channel(handle);

	/* copy binary data */
	handle = map_channel(&channel_data,
			stream_data, MAX_NR_STREAMS);
	if (!handle)
		return -1;
	for (k = 0; k < MAX_NR_STREAMS; k++) {
		snprintf(pathname, PATH_MAX - 1,
			"%s/data_%u", outputpath, k);
		ret = consume_stream(handle, k, pathname);
		if (ret && ret != -ENOENT) {
			printf("Error in consume_stream\n");
			return ret;
		}
	}
	unmap_channel(handle);

	return 0;
}

static
int send_app_msgs(int sock, const char *outputpath,
		unsigned int nr_events, const char **event_names)
{
	struct ustcomm_ust_msg lum;
	struct ustcomm_ust_reply lur;
	int ret, k;

	/* Create session */
	memset(&lum, 0, sizeof(lum));
	lum.handle = LTTNG_UST_ROOT_HANDLE;
	lum.cmd = LTTNG_UST_SESSION;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	session_handle = lur.ret_val;
	printf("received session handle %u\n", session_handle);

	/* Create metadata channel */
	memset(&lum, 0, sizeof(lum));
	lum.handle = session_handle;
	lum.cmd = LTTNG_UST_METADATA;
	lum.u.channel.overwrite = 0;
	lum.u.channel.subbuf_size = 32768;
	lum.u.channel.num_subbuf = 4;
	lum.u.channel.switch_timer_interval = 0;
	lum.u.channel.read_timer_interval = 0;
	lum.u.channel.output = LTTNG_UST_MMAP;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	metadata_data.handle = lur.ret_val;
	printf("received metadata handle %u\n", metadata_data.handle);
	if (lur.ret_code == LTTNG_UST_OK) {
		ssize_t len;

		metadata_data.memory_map_size = lur.u.channel.memory_map_size;
		/* get shm fd */
		len = ustcomm_recv_fd(sock);
		if (len < 0)
			return -EINVAL;
		metadata_data.shm_fd = len;
		/* get wait fd */
		len = ustcomm_recv_fd(sock);
		if (len < 0)
			return -EINVAL;
		metadata_data.wait_fd = len;
	}

	ret = open_streams(sock, metadata_data.handle,
			&metadata_stream_data, 1);
	if (ret) {
		printf("Error in open_streams\n");
		return ret;
	}

	/* Create data channel */
	memset(&lum, 0, sizeof(lum));
	lum.handle = session_handle;
	lum.cmd = LTTNG_UST_CHANNEL;
	//lum.u.channel.overwrite = 0;
	lum.u.channel.overwrite = 1;
	lum.u.channel.subbuf_size = 32768;
	lum.u.channel.num_subbuf = 8;
	//lum.u.channel.num_subbuf = 4;
	//lum.u.channel.num_subbuf = 2;
	lum.u.channel.switch_timer_interval = 0;
	lum.u.channel.read_timer_interval = 0;
	lum.u.channel.output = LTTNG_UST_MMAP;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	channel_data.handle = lur.ret_val;
	printf("received channel handle %u\n", channel_data.handle);
	if (lur.ret_code == LTTNG_UST_OK) {
		ssize_t len;

		channel_data.memory_map_size = lur.u.channel.memory_map_size;
		/* get shm fd */
		len = ustcomm_recv_fd(sock);
		if (len < 0)
			return -EINVAL;
		channel_data.shm_fd = len;
		/* get wait fd */
		len = ustcomm_recv_fd(sock);
		if (len < 0)
			return -EINVAL;
		channel_data.wait_fd = len;
	}

	/* Create events */
	for (k = 0; k < nr_events; k++) {
		memset(&lum, 0, sizeof(lum));
		lum.handle = channel_data.handle;
		lum.cmd = LTTNG_UST_EVENT;
		strncpy(lum.u.event.name, event_names[k],
			LTTNG_UST_SYM_NAME_LEN);
		lum.u.event.instrumentation = LTTNG_UST_TRACEPOINT;
		ret = ustcomm_send_app_cmd(sock, &lum, &lur);
		if (ret)
			return ret;
		event_handle[k] = lur.ret_val;
		printf("received event handle %u\n", event_handle[k]);
	}

	/* Attach vtid context */
	memset(&lum, 0, sizeof(lum));
	lum.handle = channel_data.handle;
	lum.cmd = LTTNG_UST_CONTEXT;
	lum.u.context.ctx = LTTNG_UST_CONTEXT_VTID;
	//lum.u.context.ctx = LTTNG_UST_CONTEXT_PTHREAD_ID;
	//lum.u.context.ctx = LTTNG_UST_CONTEXT_VPID;
	//lum.u.context.ctx = LTTNG_UST_CONTEXT_PROCNAME;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	context_handle = lur.ret_val;
	printf("received context handle %u\n", context_handle);

	/* Get references to channel streams */
	ret = open_streams(sock, channel_data.handle,
			stream_data, MAX_NR_STREAMS);
	if (ret) {
		printf("Error in open_streams\n");
		return ret;
	}

	memset(&lum, 0, sizeof(lum));
	lum.handle = session_handle;
	lum.cmd = LTTNG_UST_SESSION_START;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	printf("Session handle %u started.\n", session_handle);

	/* Tell application registration is done */
	memset(&lum, 0, sizeof(lum));
	lum.handle = LTTNG_UST_ROOT_HANDLE;
	lum.cmd = LTTNG_UST_REGISTER_DONE;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	printf("Registration done acknowledged.\n");

	sleep(4);

	ret = consume_buffers(outputpath);
	if (ret) {
		printf("Error in consume_buffers\n");
		return ret;
	}

	/* Release data channel */
	/* Release streams */
	ret = close_streams(sock, stream_data,
			MAX_NR_STREAMS);
	if (ret)
		return ret;

	/* Release context */
	memset(&lum, 0, sizeof(lum));
	lum.handle = context_handle;
	lum.cmd = LTTNG_UST_RELEASE;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;

	/* Release events */
	for (k = 0; k < nr_events; k++) {
		memset(&lum, 0, sizeof(lum));
		lum.handle = event_handle[k];
		lum.cmd = LTTNG_UST_RELEASE;
		ret = ustcomm_send_app_cmd(sock, &lum, &lur);
		if (ret)
			return ret;
	}
	memset(&lum, 0, sizeof(lum));
	lum.handle = channel_data.handle;
	lum.cmd = LTTNG_UST_RELEASE;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	if (channel_data.shm_fd >= 0) {
		ret = close(channel_data.shm_fd);
		if (ret)
			return ret;
	}
	if (channel_data.wait_fd >= 0) {
		ret = close(channel_data.wait_fd);
		if (ret)
			return ret;
	}

	/* Release metadata channel */
	ret = close_streams(sock, &metadata_stream_data, 1);
	if (ret)
		return ret;

	memset(&lum, 0, sizeof(lum));
	lum.handle = metadata_data.handle;
	lum.cmd = LTTNG_UST_RELEASE;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;
	if (metadata_data.shm_fd >= 0) {
		ret = close(metadata_data.shm_fd);
		if (ret)
			return ret;
	}
	if (metadata_data.wait_fd >= 0) {
		ret = close(metadata_data.wait_fd);
		if (ret)
			return ret;
	}

	/* Release session */
	memset(&lum, 0, sizeof(lum));
	lum.handle = session_handle;
	lum.cmd = LTTNG_UST_RELEASE;
	ret = ustcomm_send_app_cmd(sock, &lum, &lur);
	if (ret)
		return ret;

	return 0;
}

/*
 * Using fork to set umask in the child process (not multi-thread safe). We
 * deal with the shm_open vs ftruncate race (happening when the sessiond owns
 * the shm and does not let everybody modify it, to ensure safety against
 * shm_unlink) by simply letting the mmap fail and retrying after a few
 * seconds. For global shm, everybody has rw access to it until the sessiond
 * starts.
 */
static int get_wait_shm(char *shm_path, size_t mmap_size, int global)
{
	int wait_shm_fd, ret;
	mode_t mode;

	/* Default permissions */
	mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;

	/* Change owner of the shm path */
	if (global) {
		ret = chown(shm_path, 0, 0);
		if (ret < 0) {
			if (errno != ENOENT) {
				perror("chown wait shm");
				goto error;
			}
		}

		/*
		 * If global session daemon, any application can register so the shm
		 * needs to be set in read-only mode for others.
		 */
		mode |= S_IROTH;
	} else {
		ret = chown(shm_path, getuid(), getgid());
		if (ret < 0) {
			if (errno != ENOENT) {
				perror("chown wait shm");
				goto error;
			}
		}
	}

	/*
	 * Set permissions to the shm even if we did not create the shm.
	 */
	ret = chmod(shm_path, mode);
	if (ret < 0) {
		if (errno != ENOENT) {
			perror("chmod wait shm");
			goto error;
		}
	}

	/*
	 * We're alone in a child process, so we can modify the process-wide
	 * umask.
	 */
	umask(~mode);

	/*
	 * Try creating shm (or get rw access). We don't do an exclusive open,
	 * because we allow other processes to create+ftruncate it concurrently.
	 */
	wait_shm_fd = shm_open(shm_path, O_RDWR | O_CREAT, mode);
	if (wait_shm_fd < 0) {
		perror("shm_open wait shm");
		goto error;
	}

	ret = ftruncate(wait_shm_fd, mmap_size);
	if (ret < 0) {
		perror("ftruncate wait shm");
		exit(EXIT_FAILURE);
	}

	ret = fchmod(wait_shm_fd, mode);
	if (ret < 0) {
		perror("fchmod");
		exit(EXIT_FAILURE);
	}

	printf("Got the wait shm fd %d\n", wait_shm_fd);

	return wait_shm_fd;

error:
	printf("Failing to get the wait shm fd\n");

	return -1;
}

int update_futex(int fd, int active)
{
	long page_size;
	char *wait_shm_mmap;
	int ret;

	page_size = sysconf(_SC_PAGE_SIZE);
	if (page_size <= 0) {
		if (!page_size) {
			errno = EINVAL;
		}
		perror("Error in sysconf(_SC_PAGE_SIZE)");
		goto error;
	}
	wait_shm_mmap = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
		  MAP_SHARED, fd, 0);
	if (wait_shm_mmap == MAP_FAILED) {
		perror("mmap");
		goto error;
	}

	if (active) {
		uatomic_set((int32_t *) wait_shm_mmap, 1);
		if (futex_async((int32_t *) wait_shm_mmap, FUTEX_WAKE,
				INT_MAX, NULL, NULL, 0) < 0) {
			perror("futex_async");
			goto error;
		}
	} else {
		uatomic_set((int32_t *) wait_shm_mmap, 0);
	}
	ret = munmap(wait_shm_mmap, page_size);
	if (ret) {
		perror("Error unmapping wait shm");
		goto error;
	}
	return 0;
error:
	return -1;
}

/*
 * Set open files limit to unlimited. This daemon can open a large number of
 * file descriptors in order to consumer multiple kernel traces.
 */
static void set_ulimit(void)
{
	int ret;
	struct rlimit lim;

	/*
	 * If not root, we cannot increase our max open files. But our
	 * scope is then limited to processes from a single user.
	 */
	if (getuid() != 0)
		return;
	/* The kernel does not allowed an infinite limit for open files */
	lim.rlim_cur = 65535;
	lim.rlim_max = 65535;

	ret = setrlimit(RLIMIT_NOFILE, &lim);
	if (ret < 0) {
		perror("failed to set open files limit");
	}
}

/*
 * Usage:
 * ./ust-basic-tracing outputpath event_name1 event_name2 ....
 */
int main(int argc, const char **argv)
{
	const char *home_dir;
	char home_rundir[PATH_MAX];
	char *cmd = NULL;
	int ret, wait_shm_fd;
	struct sigaction act;
	mode_t old_umask = 0;
	const char *outputpath;
	const char **event_names;
	unsigned int nr_events;
	long page_size;

	if (argc < 2) {
		printf("Usage:\n");
		printf("%s outputpath event_name1 event_name2 ...\n",
			argv[0]);
		exit(-1);
	}
	outputpath = argv[1];
	event_names = &argv[2];
	nr_events = argc - 2;

	set_ulimit();

	/* Ignore sigpipe */
	memset(&act, 0, sizeof(act));
	ret = sigemptyset(&act.sa_mask);
	if (ret == -1) {
		perror("sigemptyset");
		return -1;
	}

	act.sa_handler = SIG_IGN;
	ret = sigaction(SIGPIPE, &act, NULL);
	if (ret == -1) {
		perror("sigaction");
		return -1;
	}

	/* Handle SIGTERM */
	act.sa_handler = handle_signals;
	ret = sigaction(SIGTERM, &act, NULL);
	if (ret == -1) {
		perror("sigaction");
		return -1;
	}
	/* Handle SIGINT */
	ret = sigaction(SIGINT, &act, NULL);
	if (ret == -1) {
		perror("sigaction");
		return -1;
	}

	page_size = sysconf(_SC_PAGE_SIZE);
	if (page_size <= 0) {
		if (!page_size) {
			errno = EINVAL;
		}
		perror("Error in sysconf(_SC_PAGE_SIZE)");
		return -1;
	}

	if (geteuid() == 0) {
		ret = mkdir(LTTNG_RUNDIR, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
		if (ret && errno != EEXIST) {
			perror("mkdir");
			return -1;
		}
		wait_shm_fd = get_wait_shm(DEFAULT_GLOBAL_APPS_WAIT_SHM_PATH,
					page_size, 1);
		if (wait_shm_fd < 0) {
			perror("global wait shm error");
			return -1;
		}
		strcpy(apps_sock_path, DEFAULT_GLOBAL_APPS_UNIX_SOCK);
		old_umask = umask(0);
	} else {
		home_dir = (const char *) getenv("HOME");
		if (!home_dir) {
			perror("getenv error");
			return -ENOENT;
		}

		snprintf(home_rundir, PATH_MAX,
			 LTTNG_HOME_RUNDIR, home_dir);

		ret = mkdir(home_rundir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
		if (ret && errno != EEXIST) {
			perror("mkdir");
			return -1;
		}

		snprintf(local_apps_wait_shm_path, PATH_MAX,
			 DEFAULT_HOME_APPS_WAIT_SHM_PATH, getuid());
		wait_shm_fd = get_wait_shm(local_apps_wait_shm_path,
					page_size, 0);
		if (wait_shm_fd < 0) {
			perror("local wait shm error");
			return -1;
		}
		snprintf(apps_sock_path, PATH_MAX,
			 DEFAULT_HOME_APPS_UNIX_SOCK, home_dir);
	}

	ret = ustcomm_create_unix_sock(apps_sock_path);
	if (ret < 0) {
		perror("create error");
		return ret;
	}
	apps_socket = ret;

	if (getuid() == 0) {
		/* File permission MUST be 666 */
		ret = chmod(apps_sock_path,
				S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
		if (ret < 0) {
			printf("Set file permissions failed: %s\n", apps_sock_path);
			perror("chmod");
			goto end;
		}
		umask(old_umask);
	}
	ret = ustcomm_listen_unix_sock(apps_socket);
	if (ret < 0) {
		perror("listen error");
		return ret;
	}

	/* wake up futexes */
	ret = update_futex(wait_shm_fd, 1);
	if (ret) {
		fprintf(stderr, "Error wakeup futex\n");
		return -1;
	}

	for (;;) {
		int sock;
		ssize_t len;
		struct {
			uint32_t major;
			uint32_t minor;
			pid_t pid;
			pid_t ppid;
			uid_t uid;
			gid_t gid;
			uint32_t bits_per_long;
			char name[16];	/* Process name */
		} reg_msg;
		char bufname[17];

		if (quit_program)
			break;

		printf("Accepting application registration\n");
		sock = ustcomm_accept_unix_sock(apps_socket);
		if (sock < 0) {
			perror("accept error");
			goto end;
		}

		/*
		 * Basic recv here to handle the very simple data
		 * that the libust send to register (reg_msg).
		 */
		len = ustcomm_recv_unix_sock(sock, &reg_msg, sizeof(reg_msg));
		if (len < 0 || len != sizeof(reg_msg)) {
			perror("ustcomm_recv_unix_sock");
			continue;
		}
		memcpy(bufname, reg_msg.name, 16);
		bufname[16] = '\0';
		printf("Application %s pid %u ppid %u uid %u gid %u has registered (version : %u.%u)\n",
			bufname, reg_msg.pid, reg_msg.ppid, reg_msg.uid,
			reg_msg.gid, reg_msg.major, reg_msg.minor);
		ret = send_app_msgs(sock, outputpath, nr_events, event_names);
		if (ret) {
			printf("Error in send_app_msgs.\n");
			sleep(1);
		}
		close(sock);
	}

end:
	printf("quitting.\n");
	/* Let applications know we are not responding anymore */
	ret = update_futex(wait_shm_fd, 0);
	if (ret) {
		fprintf(stderr, "Error wakeup futex\n");
		return -1;
	}

	if (geteuid()) {
		printf("Removing %s directory\n", home_rundir);
		ret = asprintf(&cmd, "rm -rf %s", home_rundir);
		if (ret < 0) {
			printf("asprintf failed. Something is really wrong!\n");
			return -1;
		}

		/* Remove lttng run directory */
		ret = system(cmd);
		if (ret < 0) {
			printf("Unable to clean %s\n", home_rundir);
			return -1;
		}
	}


	return 0;
}
