/* Copyright (C) 2009  Pierre-Marc Fournier
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

/* This file contains the implementation of the UST listener thread, which
 * receives trace control commands. It also coordinates the initialization of
 * libust.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <poll.h>
#include <regex.h>
#include <urcu/uatomic_arch.h>
#include <urcu/list.h>

#include <ust/marker.h>
#include <ust/tracepoint.h>
#include <ust/tracectl.h>
#include <ust/clock.h>
#include "tracer.h"
#include "usterr.h"
#include "ustcomm.h"
#include "buffers.h"
#include "marker-control.h"

/* This should only be accessed by the constructor, before the creation
 * of the listener, and then only by the listener.
 */
s64 pidunique = -1LL;

/* The process pid is used to detect a non-traceable fork
 * and allow the non-traceable fork to be ignored
 * by destructor sequences in libust
 */
static pid_t processpid = 0;

static struct ustcomm_header _receive_header;
static struct ustcomm_header *receive_header = &_receive_header;
static char receive_buffer[USTCOMM_BUFFER_SIZE];
static char send_buffer[USTCOMM_BUFFER_SIZE];

static int epoll_fd;

/*
 * Listener thread data vs fork() protection mechanism. Ensures that no listener
 * thread mutexes and data structures are being concurrently modified or held by
 * other threads when fork() is executed.
 */
static pthread_mutex_t listener_thread_data_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Mutex protecting listen_sock. Nests inside listener_thread_data_mutex. */
static pthread_mutex_t listen_sock_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct ustcomm_sock *listen_sock;

extern struct chan_info_struct chan_infos[];

static struct cds_list_head ust_socks = CDS_LIST_HEAD_INIT(ust_socks);

/* volatile because shared between the listener and the main thread */
int buffers_to_export = 0;

int ust_clock_source;

static long long make_pidunique(void)
{
	s64 retval;
	struct timeval tv;

	gettimeofday(&tv, NULL);

	retval = tv.tv_sec;
	retval <<= 32;
	retval |= tv.tv_usec;

	return retval;
}

static void print_markers(FILE *fp)
{
	struct marker_iter iter;

	lock_markers();
	marker_iter_reset(&iter);
	marker_iter_start(&iter);

	while (iter.marker) {
		fprintf(fp, "marker: %s/%s %d \"%s\" %p\n",
			(*iter.marker)->channel,
			(*iter.marker)->name,
			(int)imv_read((*iter.marker)->state),
			(*iter.marker)->format,
			(*iter.marker)->location);
		marker_iter_next(&iter);
	}
	unlock_markers();
}

static void print_trace_events(FILE *fp)
{
	struct trace_event_iter iter;

	lock_trace_events();
	trace_event_iter_reset(&iter);
	trace_event_iter_start(&iter);

	while (iter.trace_event) {
		fprintf(fp, "trace_event: %s\n", (*iter.trace_event)->name);
		trace_event_iter_next(&iter);
	}
	unlock_trace_events();
}

static int connect_ustconsumer(void)
{
	int result, fd;
	char default_daemon_path[] = SOCK_DIR "/ustconsumer";
	char *explicit_daemon_path, *daemon_path;

	explicit_daemon_path = getenv("UST_DAEMON_SOCKET");
	if (explicit_daemon_path) {
		daemon_path = explicit_daemon_path;
	} else {
		daemon_path = default_daemon_path;
	}

	DBG("Connecting to daemon_path %s", daemon_path);

	result = ustcomm_connect_path(daemon_path, &fd);
	if (result < 0) {
		WARN("connect_ustconsumer failed, daemon_path: %s",
		     daemon_path);
		return result;
	}

	return fd;
}


static void request_buffer_consumer(int sock,
				    const char *trace,
				    const char *channel,
				    int cpu)
{
	struct ustcomm_header send_header, recv_header;
	struct ustcomm_buffer_info buf_inf;
	int result = 0;

	result = ustcomm_pack_buffer_info(&send_header,
					  &buf_inf,
					  trace,
					  channel,
					  cpu);

	if (result < 0) {
		ERR("failed to pack buffer info message %s_%d",
		    channel, cpu);
		return;
	}

	buf_inf.pid = getpid();
	send_header.command = CONSUME_BUFFER;

	result = ustcomm_req(sock, &send_header, (char *) &buf_inf,
			     &recv_header, NULL);
	if (result <= 0) {
		PERROR("request for buffer consumer failed, is the daemon online?");
	}

	return;
}

/* Ask the daemon to collect a trace called trace_name and being
 * produced by this pid.
 *
 * The trace must be at least allocated. (It can also be started.)
 * This is because _ltt_trace_find is used.
 */

static void inform_consumer_daemon(const char *trace_name)
{
	int sock, i,j;
	struct ust_trace *trace;
	const char *ch_name;

	sock = connect_ustconsumer();
	if (sock < 0) {
		return;
	}

	DBG("Connected to ustconsumer");

	ltt_lock_traces();

	trace = _ltt_trace_find(trace_name);
	if (trace == NULL) {
		WARN("inform_consumer_daemon: could not find trace \"%s\"; it is probably already destroyed", trace_name);
		goto unlock_traces;
	}

	for (i=0; i < trace->nr_channels; i++) {
		if (trace->channels[i].request_collection) {
			/* iterate on all cpus */
			for (j=0; j<trace->channels[i].n_cpus; j++) {
				ch_name = trace->channels[i].channel_name;
				request_buffer_consumer(sock, trace_name,
							ch_name, j);
				CMM_STORE_SHARED(buffers_to_export,
					     CMM_LOAD_SHARED(buffers_to_export)+1);
			}
		}
	}

unlock_traces:
	ltt_unlock_traces();

	close(sock);
}

static struct ust_channel *find_channel(const char *ch_name,
					struct ust_trace *trace)
{
	int i;

	for (i=0; i<trace->nr_channels; i++) {
		if (!strcmp(trace->channels[i].channel_name, ch_name)) {
			return &trace->channels[i];
		}
	}

	return NULL;
}

static int get_buffer_shmid_pipe_fd(const char *trace_name, const char *ch_name,
				    int ch_cpu,
				    int *buf_shmid,
				    int *buf_struct_shmid,
				    int *buf_pipe_fd)
{
	struct ust_trace *trace;
	struct ust_channel *channel;
	struct ust_buffer *buf;

	DBG("get_buffer_shmid_pipe_fd");

	ltt_lock_traces();
	trace = _ltt_trace_find(trace_name);
	ltt_unlock_traces();

	if (trace == NULL) {
		ERR("cannot find trace!");
		return -ENODATA;
	}

	channel = find_channel(ch_name, trace);
	if (!channel) {
		ERR("cannot find channel %s!", ch_name);
		return -ENODATA;
	}

	buf = channel->buf[ch_cpu];

	*buf_shmid = buf->shmid;
	*buf_struct_shmid = channel->buf_struct_shmids[ch_cpu];
	*buf_pipe_fd = buf->data_ready_fd_read;

	return 0;
}

static int get_subbuf_num_size(const char *trace_name, const char *ch_name,
			       int *num, int *size)
{
	struct ust_trace *trace;
	struct ust_channel *channel;

	DBG("get_subbuf_size");

	ltt_lock_traces();
	trace = _ltt_trace_find(trace_name);
	ltt_unlock_traces();

	if (!trace) {
		ERR("cannot find trace!");
		return -ENODATA;
	}

	channel = find_channel(ch_name, trace);
	if (!channel) {
		ERR("unable to find channel");
		return -ENODATA;
	}

	*num = channel->subbuf_cnt;
	*size = channel->subbuf_size;

	return 0;
}

/* Return the power of two which is equal or higher to v */

static unsigned int pow2_higher_or_eq(unsigned int v)
{
	int hb = fls(v);
	int retval = 1<<(hb-1);

	if (v-retval == 0)
		return retval;
	else
		return retval<<1;
}

static int set_subbuf_size(const char *trace_name, const char *ch_name,
			   unsigned int size)
{
	unsigned int power;
	int retval = 0;
	struct ust_trace *trace;
	struct ust_channel *channel;

	DBG("set_subbuf_size");

	power = pow2_higher_or_eq(size);
	power = max_t(unsigned int, 2u, power);
	if (power != size) {
		WARN("using the next power of two for buffer size = %u\n", power);
	}

	ltt_lock_traces();
	trace = _ltt_trace_find_setup(trace_name);
	if (trace == NULL) {
		ERR("cannot find trace!");
		retval = -ENODATA;
		goto unlock_traces;
	}

	channel = find_channel(ch_name, trace);
	if (!channel) {
		ERR("unable to find channel");
		retval = -ENODATA;
		goto unlock_traces;
	}

	channel->subbuf_size = power;
	DBG("the set_subbuf_size for the requested channel is %zu", channel->subbuf_size);

unlock_traces:
	ltt_unlock_traces();

	return retval;
}

static int set_subbuf_num(const char *trace_name, const char *ch_name,
				 unsigned int num)
{
	struct ust_trace *trace;
	struct ust_channel *channel;
	int retval = 0;

	DBG("set_subbuf_num");

	if (num < 2) {
		ERR("subbuffer count should be greater than 2");
		return -EINVAL;
	}

	ltt_lock_traces();
	trace = _ltt_trace_find_setup(trace_name);
	if (trace == NULL) {
		ERR("cannot find trace!");
		retval = -ENODATA;
		goto unlock_traces;
	}

	channel = find_channel(ch_name, trace);
	if (!channel) {
		ERR("unable to find channel");
		retval = -ENODATA;
		goto unlock_traces;
	}

	channel->subbuf_cnt = num;
	DBG("the set_subbuf_cnt for the requested channel is %u", channel->subbuf_cnt);

unlock_traces:
	ltt_unlock_traces();
	return retval;
}

static int get_subbuffer(const char *trace_name, const char *ch_name,
			 int ch_cpu, long *consumed_old)
{
	int retval = 0;
	struct ust_trace *trace;
	struct ust_channel *channel;
	struct ust_buffer *buf;

	DBG("get_subbuf");

	*consumed_old = 0;

	ltt_lock_traces();
	trace = _ltt_trace_find(trace_name);

	if (!trace) {
		DBG("Cannot find trace. It was likely destroyed by the user.");
		retval = -ENODATA;
		goto unlock_traces;
	}

	channel = find_channel(ch_name, trace);
	if (!channel) {
		ERR("unable to find channel");
		retval = -ENODATA;
		goto unlock_traces;
	}

	buf = channel->buf[ch_cpu];

	retval = ust_buffers_get_subbuf(buf, consumed_old);
	if (retval < 0) {
		WARN("missed buffer?");
	}

unlock_traces:
	ltt_unlock_traces();

	return retval;
}


static int notify_buffer_mapped(const char *trace_name,
				const char *ch_name,
				int ch_cpu)
{
	int retval = 0;
	struct ust_trace *trace;
	struct ust_channel *channel;
	struct ust_buffer *buf;

	DBG("get_buffer_fd");

	ltt_lock_traces();
	trace = _ltt_trace_find(trace_name);

	if (!trace) {
		retval = -ENODATA;
		DBG("Cannot find trace. It was likely destroyed by the user.");
		goto unlock_traces;
	}

	channel = find_channel(ch_name, trace);
	if (!channel) {
		retval = -ENODATA;
		ERR("unable to find channel");
		goto unlock_traces;
	}

	buf = channel->buf[ch_cpu];

	/* Being here is the proof the daemon has mapped the buffer in its
	 * memory. We may now decrement buffers_to_export.
	 */
	if (uatomic_read(&buf->consumed) == 0) {
		DBG("decrementing buffers_to_export");
		CMM_STORE_SHARED(buffers_to_export, CMM_LOAD_SHARED(buffers_to_export)-1);
	}

unlock_traces:
	ltt_unlock_traces();

	return retval;
}

static int put_subbuffer(const char *trace_name, const char *ch_name,
			 int ch_cpu, long consumed_old)
{
	int retval = 0;
	struct ust_trace *trace;
	struct ust_channel *channel;
	struct ust_buffer *buf;

	DBG("put_subbuf");

	ltt_lock_traces();
	trace = _ltt_trace_find(trace_name);

	if (!trace) {
		retval = -ENODATA;
		DBG("Cannot find trace. It was likely destroyed by the user.");
		goto unlock_traces;
	}

	channel = find_channel(ch_name, trace);
	if (!channel) {
		retval = -ENODATA;
		ERR("unable to find channel");
		goto unlock_traces;
	}

	buf = channel->buf[ch_cpu];

	retval = ust_buffers_put_subbuf(buf, consumed_old);
	if (retval < 0) {
		WARN("ust_buffers_put_subbuf: error (subbuf=%s_%d)",
		     ch_name, ch_cpu);
	} else {
		DBG("ust_buffers_put_subbuf: success (subbuf=%s_%d)",
		    ch_name, ch_cpu);
	}

unlock_traces:
	ltt_unlock_traces();

	return retval;
}

static void release_listener_mutex(void *ptr)
{
	pthread_mutex_unlock(&listener_thread_data_mutex);
}

static void listener_cleanup(void *ptr)
{
	pthread_mutex_lock(&listen_sock_mutex);
	if (listen_sock) {
		ustcomm_del_named_sock(listen_sock, 0);
		listen_sock = NULL;
	}
	pthread_mutex_unlock(&listen_sock_mutex);
}

static int force_subbuf_switch(const char *trace_name)
{
	struct ust_trace *trace;
	int i, j, retval = 0;

	ltt_lock_traces();
	trace = _ltt_trace_find(trace_name);
	if (!trace) {
                retval = -ENODATA;
                DBG("Cannot find trace. It was likely destroyed by the user.");
                goto unlock_traces;
        }

	for (i = 0; i < trace->nr_channels; i++) {
		for (j = 0; j < trace->channels[i].n_cpus; j++) {
			ltt_force_switch(trace->channels[i].buf[j],
					 FORCE_FLUSH);
		}
	}

unlock_traces:
	ltt_unlock_traces();

	return retval;
}

static int process_trace_cmd(int command, char *trace_name)
{
	int result;
	char trace_type[] = "ustrelay";

	switch(command) {
	case START:
		/* start is an operation that setups the trace, allocates it and starts it */
		result = ltt_trace_setup(trace_name);
		if (result < 0) {
			ERR("ltt_trace_setup failed");
			return result;
		}

		result = ltt_trace_set_type(trace_name, trace_type);
		if (result < 0) {
			ERR("ltt_trace_set_type failed");
			return result;
		}

		result = ltt_trace_alloc(trace_name);
		if (result < 0) {
			ERR("ltt_trace_alloc failed");
			return result;
		}

		inform_consumer_daemon(trace_name);

		result = ltt_trace_start(trace_name);
		if (result < 0) {
			ERR("ltt_trace_start failed");
			return result;
		}

		return 0;
	case SETUP_TRACE:
		DBG("trace setup");

		result = ltt_trace_setup(trace_name);
		if (result < 0) {
			ERR("ltt_trace_setup failed");
			return result;
		}

		result = ltt_trace_set_type(trace_name, trace_type);
		if (result < 0) {
			ERR("ltt_trace_set_type failed");
			return result;
		}

		return 0;
	case ALLOC_TRACE:
		DBG("trace alloc");

		result = ltt_trace_alloc(trace_name);
		if (result < 0) {
			ERR("ltt_trace_alloc failed");
			return result;
		}
		inform_consumer_daemon(trace_name);

		return 0;

	case CREATE_TRACE:
		DBG("trace create");

		result = ltt_trace_setup(trace_name);
		if (result < 0) {
			ERR("ltt_trace_setup failed");
			return result;
		}

		result = ltt_trace_set_type(trace_name, trace_type);
		if (result < 0) {
			ERR("ltt_trace_set_type failed");
			return result;
		}

		return 0;
	case START_TRACE:
		DBG("trace start");

		result = ltt_trace_alloc(trace_name);
		if (result < 0) {
			ERR("ltt_trace_alloc failed");
			return result;
		}
		if (!result) {
			inform_consumer_daemon(trace_name);
		}

		result = ltt_trace_start(trace_name);
		if (result < 0) {
			ERR("ltt_trace_start failed");
			return result;
		}

		return 0;
	case STOP_TRACE:
		DBG("trace stop");

		result = ltt_trace_stop(trace_name);
		if (result < 0) {
			ERR("ltt_trace_stop failed");
			return result;
		}

		return 0;
	case DESTROY_TRACE:
		DBG("trace destroy");

		result = ltt_trace_destroy(trace_name, 0);
		if (result < 0) {
			ERR("ltt_trace_destroy failed");
			return result;
		}
		return 0;
	case FORCE_SUBBUF_SWITCH:
		DBG("force switch");

		result = force_subbuf_switch(trace_name);
		if (result < 0) {
			ERR("force_subbuf_switch failed");
			return result;
		}
		return 0;
	}

	return 0;
}


static void process_channel_cmd(int sock, int command,
				struct ustcomm_channel_info *ch_inf)
{
	struct ustcomm_header _reply_header;
	struct ustcomm_header *reply_header = &_reply_header;
	struct ustcomm_channel_info *reply_msg =
		(struct ustcomm_channel_info *)send_buffer;
	int result, offset = 0, num, size;

	memset(reply_header, 0, sizeof(*reply_header));

	switch (command) {
	case GET_SUBBUF_NUM_SIZE:
		result = get_subbuf_num_size(ch_inf->trace,
					     ch_inf->channel,
					     &num, &size);
		if (result < 0) {
			reply_header->result = result;
			break;
		}

		reply_msg->channel = USTCOMM_POISON_PTR;
		reply_msg->subbuf_num = num;
		reply_msg->subbuf_size = size;


		reply_header->size = COMPUTE_MSG_SIZE(reply_msg, offset);

		break;
	case SET_SUBBUF_NUM:
		reply_header->result = set_subbuf_num(ch_inf->trace,
						      ch_inf->channel,
						      ch_inf->subbuf_num);

		break;
	case SET_SUBBUF_SIZE:
		reply_header->result = set_subbuf_size(ch_inf->trace,
						       ch_inf->channel,
						       ch_inf->subbuf_size);


		break;
	}
	if (ustcomm_send(sock, reply_header, (char *)reply_msg) < 0) {
		ERR("ustcomm_send failed");
	}
}

static void process_buffer_cmd(int sock, int command,
			       struct ustcomm_buffer_info *buf_inf)
{
	struct ustcomm_header _reply_header;
	struct ustcomm_header *reply_header = &_reply_header;
	struct ustcomm_buffer_info *reply_msg =
		(struct ustcomm_buffer_info *)send_buffer;
	int result, offset = 0, buf_shmid, buf_struct_shmid, buf_pipe_fd;
	long consumed_old;

	memset(reply_header, 0, sizeof(*reply_header));

	switch (command) {
	case GET_BUF_SHMID_PIPE_FD:
		result = get_buffer_shmid_pipe_fd(buf_inf->trace,
						  buf_inf->channel,
						  buf_inf->ch_cpu,
						  &buf_shmid,
						  &buf_struct_shmid,
						  &buf_pipe_fd);
		if (result < 0) {
			reply_header->result = result;
			break;
		}

		reply_msg->channel = USTCOMM_POISON_PTR;
		reply_msg->buf_shmid = buf_shmid;
		reply_msg->buf_struct_shmid = buf_struct_shmid;

		reply_header->size = COMPUTE_MSG_SIZE(reply_msg, offset);
		reply_header->fd_included = 1;

		if (ustcomm_send_fd(sock, reply_header, (char *)reply_msg,
				    &buf_pipe_fd) < 0) {
			ERR("ustcomm_send failed");
		}
		return;

	case NOTIFY_BUF_MAPPED:
		reply_header->result =
			notify_buffer_mapped(buf_inf->trace,
					     buf_inf->channel,
					     buf_inf->ch_cpu);
		break;
	case GET_SUBBUFFER:
		result = get_subbuffer(buf_inf->trace, buf_inf->channel,
				       buf_inf->ch_cpu, &consumed_old);
		if (result < 0) {
			reply_header->result = result;
			break;
		}

		reply_msg->channel = USTCOMM_POISON_PTR;
		reply_msg->consumed_old = consumed_old;

		reply_header->size = COMPUTE_MSG_SIZE(reply_msg, offset);

		break;
	case PUT_SUBBUFFER:
		result = put_subbuffer(buf_inf->trace, buf_inf->channel,
				       buf_inf->ch_cpu,
				       buf_inf->consumed_old);
		reply_header->result = result;

		break;
	}

	if (ustcomm_send(sock, reply_header, (char *)reply_msg) < 0) {
		ERR("ustcomm_send failed");
	}

}

static void process_marker_cmd(int sock, int command,
			       struct ustcomm_marker_info *marker_inf)
{
	struct ustcomm_header _reply_header;
	struct ustcomm_header *reply_header = &_reply_header;
	int result = 0;

	memset(reply_header, 0, sizeof(*reply_header));

	switch(command) {
	case ENABLE_MARKER:

		result = ltt_marker_connect(marker_inf->channel,
					    marker_inf->marker,
					    "default");
		if (result < 0) {
			WARN("could not enable marker; channel=%s,"
			     " name=%s",
			     marker_inf->channel,
			     marker_inf->marker);

		}
		break;
	case DISABLE_MARKER:
		result = ltt_marker_disconnect(marker_inf->channel,
					       marker_inf->marker,
					       "default");
		if (result < 0) {
			WARN("could not disable marker; channel=%s,"
			     " name=%s",
			     marker_inf->channel,
			     marker_inf->marker);
		}
		break;
	}

	reply_header->result = result;

	if (ustcomm_send(sock, reply_header, NULL) < 0) {
		ERR("ustcomm_send failed");
	}

}
static void process_client_cmd(struct ustcomm_header *recv_header,
			       char *recv_buf, int sock)
{
	int result;
	struct ustcomm_header _reply_header;
	struct ustcomm_header *reply_header = &_reply_header;
	char *send_buf = send_buffer;

	memset(reply_header, 0, sizeof(*reply_header));
	memset(send_buf, 0, sizeof(send_buffer));

	switch(recv_header->command) {
	case GET_SUBBUF_NUM_SIZE:
	case SET_SUBBUF_NUM:
	case SET_SUBBUF_SIZE:
	{
		struct ustcomm_channel_info *ch_inf;
		ch_inf = (struct ustcomm_channel_info *)recv_buf;
		result = ustcomm_unpack_channel_info(ch_inf);
		if (result < 0) {
			ERR("couldn't unpack channel info");
			reply_header->result = -EINVAL;
			goto send_response;
		}
		process_channel_cmd(sock, recv_header->command, ch_inf);
		return;
	}
	case GET_BUF_SHMID_PIPE_FD:
	case NOTIFY_BUF_MAPPED:
	case GET_SUBBUFFER:
	case PUT_SUBBUFFER:
	{
		struct ustcomm_buffer_info *buf_inf;
		buf_inf = (struct ustcomm_buffer_info *)recv_buf;
		result = ustcomm_unpack_buffer_info(buf_inf);
		if (result < 0) {
			ERR("couldn't unpack buffer info");
			reply_header->result = -EINVAL;
			goto send_response;
		}
		process_buffer_cmd(sock, recv_header->command, buf_inf);
		return;
	}
	case ENABLE_MARKER:
	case DISABLE_MARKER:
	{
		struct ustcomm_marker_info *marker_inf;
		marker_inf = (struct ustcomm_marker_info *)recv_buf;
		result = ustcomm_unpack_marker_info(marker_inf);
		if (result < 0) {
			ERR("couldn't unpack marker info");
			reply_header->result = -EINVAL;
			goto send_response;
		}
		process_marker_cmd(sock, recv_header->command, marker_inf);
		return;
	}
	case LIST_MARKERS:
	{
		char *ptr;
		size_t size;
		FILE *fp;

		fp = open_memstream(&ptr, &size);
		if (fp == NULL) {
			ERR("opening memstream failed");
			return;
		}
		print_markers(fp);
		fclose(fp);

		reply_header->size = size + 1;	/* Include final \0 */

		result = ustcomm_send(sock, reply_header, ptr);

		free(ptr);

		if (result < 0) {
			PERROR("failed to send markers list");
		}

		break;
	}
	case LIST_TRACE_EVENTS:
	{
		char *ptr;
		size_t size;
		FILE *fp;

		fp = open_memstream(&ptr, &size);
		if (fp == NULL) {
			ERR("opening memstream failed");
			return;
		}
		print_trace_events(fp);
		fclose(fp);

		reply_header->size = size + 1;	/* Include final \0 */

		result = ustcomm_send(sock, reply_header, ptr);

		free(ptr);

		if (result < 0) {
			ERR("list_trace_events failed");
			return;
		}

		break;
	}
	case LOAD_PROBE_LIB:
	{
		char *libfile;

		/* FIXME: No functionality at all... */
		libfile = recv_buf;

		DBG("load_probe_lib loading %s", libfile);

		break;
	}
	case GET_PIDUNIQUE:
	{
		struct ustcomm_pidunique *pid_msg;
		pid_msg = (struct ustcomm_pidunique *)send_buf;

		pid_msg->pidunique = pidunique;
		reply_header->size = sizeof(pid_msg);

		goto send_response;

	}
	case GET_SOCK_PATH:
	{
		struct ustcomm_single_field *sock_msg;
		char *sock_path_env;

		sock_msg = (struct ustcomm_single_field *)send_buf;

		sock_path_env = getenv("UST_DAEMON_SOCKET");

		if (!sock_path_env) {
			result = ustcomm_pack_single_field(reply_header,
							   sock_msg,
							   SOCK_DIR "/ustconsumer");

		} else {
			result = ustcomm_pack_single_field(reply_header,
							   sock_msg,
							   sock_path_env);
		}
		reply_header->result = result;

		goto send_response;
	}
	case SET_SOCK_PATH:
	{
		struct ustcomm_single_field *sock_msg;
		sock_msg = (struct ustcomm_single_field *)recv_buf;
		result = ustcomm_unpack_single_field(sock_msg);
		if (result < 0) {
			reply_header->result = -EINVAL;
			goto send_response;
		}

		reply_header->result = setenv("UST_DAEMON_SOCKET",
					      sock_msg->field, 1);

		goto send_response;
	}
	case START:
	case SETUP_TRACE:
	case ALLOC_TRACE:
	case CREATE_TRACE:
	case START_TRACE:
	case STOP_TRACE:
	case DESTROY_TRACE:
	case FORCE_SUBBUF_SWITCH:
	{
		struct ustcomm_single_field *trace_inf =
			(struct ustcomm_single_field *)recv_buf;

		result = ustcomm_unpack_single_field(trace_inf);
		if (result < 0) {
			ERR("couldn't unpack trace info");
			reply_header->result = -EINVAL;
			goto send_response;
		}

		reply_header->result =
			process_trace_cmd(recv_header->command,
					  trace_inf->field);
		goto send_response;

	}
	default:
		reply_header->result = -EINVAL;

		goto send_response;
	}

	return;

send_response:
	ustcomm_send(sock, reply_header, send_buf);
}

#define MAX_EVENTS 10

void *listener_main(void *p)
{
	struct ustcomm_sock *epoll_sock;
	struct epoll_event events[MAX_EVENTS];
	struct sockaddr addr;
	int accept_fd, nfds, result, i, addr_size;

	DBG("LISTENER");

	pthread_cleanup_push(listener_cleanup, NULL);

	for(;;) {
		nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
		if (nfds == -1) {
			PERROR("listener_main: epoll_wait failed");
			continue;
		}

		for (i = 0; i < nfds; i++) {
			pthread_mutex_lock(&listener_thread_data_mutex);
			pthread_cleanup_push(release_listener_mutex, NULL);
			epoll_sock = (struct ustcomm_sock *)events[i].data.ptr;
			if (epoll_sock == listen_sock) {
				addr_size = sizeof(struct sockaddr);
				accept_fd = accept(epoll_sock->fd,
						   &addr,
						   (socklen_t *)&addr_size);
				if (accept_fd == -1) {
					PERROR("listener_main: accept failed");
					continue;
				}
				ustcomm_init_sock(accept_fd, epoll_fd,
						 &ust_socks);
			} else {
				memset(receive_header, 0,
				       sizeof(*receive_header));
				memset(receive_buffer, 0,
				       sizeof(receive_buffer));
				result = ustcomm_recv(epoll_sock->fd,
						      receive_header,
						      receive_buffer);
				if (result == 0) {
					ustcomm_del_sock(epoll_sock, 0);
				} else {
					process_client_cmd(receive_header,
							   receive_buffer,
							   epoll_sock->fd);
				}
			}
			pthread_cleanup_pop(1);	/* release listener mutex */
		}
	}

	pthread_cleanup_pop(1);
}

/* These should only be accessed in the parent thread,
 * not the listener.
 */
static volatile sig_atomic_t have_listener = 0;
static pthread_t listener_thread;

void create_listener(void)
{
	int result;
	sigset_t sig_all_blocked;
	sigset_t orig_parent_mask;

	if (have_listener) {
		WARN("not creating listener because we already had one");
		return;
	}

	/* A new thread created by pthread_create inherits the signal mask
	 * from the parent. To avoid any signal being received by the
	 * listener thread, we block all signals temporarily in the parent,
	 * while we create the listener thread.
	 */

	sigfillset(&sig_all_blocked);

	result = pthread_sigmask(SIG_SETMASK, &sig_all_blocked, &orig_parent_mask);
	if (result) {
		PERROR("pthread_sigmask: %s", strerror(result));
	}

	result = pthread_create(&listener_thread, NULL, listener_main, NULL);
	if (result == -1) {
		PERROR("pthread_create");
	}

	/* Restore original signal mask in parent */
	result = pthread_sigmask(SIG_SETMASK, &orig_parent_mask, NULL);
	if (result) {
		PERROR("pthread_sigmask: %s", strerror(result));
	} else {
		have_listener = 1;
	}
}

#define AUTOPROBE_DISABLED      0
#define AUTOPROBE_ENABLE_ALL    1
#define AUTOPROBE_ENABLE_REGEX  2
static int autoprobe_method = AUTOPROBE_DISABLED;
static regex_t autoprobe_regex;

static void auto_probe_connect(struct marker *m)
{
	int result;

	char* concat_name = NULL;
	const char *probe_name = "default";

	if (autoprobe_method == AUTOPROBE_DISABLED) {
		return;
	} else if (autoprobe_method == AUTOPROBE_ENABLE_REGEX) {
		result = asprintf(&concat_name, "%s/%s", m->channel, m->name);
		if (result == -1) {
			ERR("auto_probe_connect: asprintf failed (marker %s/%s)",
				m->channel, m->name);
			return;
		}
		if (regexec(&autoprobe_regex, concat_name, 0, NULL, 0)) {
			free(concat_name);
			return;
		}
		free(concat_name);
	}

	result = ltt_marker_connect(m->channel, m->name, probe_name);
	if (result && result != -EEXIST)
		ERR("ltt_marker_connect (marker = %s/%s, errno = %d)", m->channel, m->name, -result);

	DBG("auto connected marker %s (addr: %p) %s to probe default", m->channel, m, m->name);

}

static struct ustcomm_sock * init_app_socket(int epoll_fd)
{
	char *dir_name, *sock_name;
	int result;
	struct ustcomm_sock *sock = NULL;

	dir_name = ustcomm_user_sock_dir();
	if (!dir_name)
		return NULL;

	result = asprintf(&sock_name, "%s/%d", dir_name, (int)getpid());
	if (result < 0) {
		ERR("string overflow allocating socket name, "
		    "UST thread bailing");
		goto free_dir_name;
	}

	result = ensure_dir_exists(dir_name);
	if (result == -1) {
		ERR("Unable to create socket directory %s, UST thread bailing",
		    dir_name);
		goto free_sock_name;
	}

	sock = ustcomm_init_named_socket(sock_name, epoll_fd);
	if (!sock) {
		ERR("Error initializing named socket (%s). Check that directory"
		    "exists and that it is writable. UST thread bailing", sock_name);
		goto free_sock_name;
	}

free_sock_name:
	free(sock_name);
free_dir_name:
	free(dir_name);

	return sock;
}

static void __attribute__((constructor)) init()
{
	struct timespec ts;
	int result;
	char* autoprobe_val = NULL;
	char* subbuffer_size_val = NULL;
	char* subbuffer_count_val = NULL;
	unsigned int subbuffer_size;
	unsigned int subbuffer_count;
	unsigned int power;

	/* Assign the pidunique, to be able to differentiate the processes with same
	 * pid, (before and after an exec).
	 */
	pidunique = make_pidunique();
	processpid = getpid();

	DBG("Tracectl constructor");

	/* Set up epoll */
	epoll_fd = epoll_create(MAX_EVENTS);
	if (epoll_fd == -1) {
		ERR("epoll_create failed, tracing shutting down");
		return;
	}

	/* Create the socket */
	listen_sock = init_app_socket(epoll_fd);
	if (!listen_sock) {
		ERR("failed to create application socket,"
		    " tracing shutting down");
		return;
	}

	create_listener();

	/* Get clock the clock source type */

	/* Default clock source */
	ust_clock_source = CLOCK_TRACE;
	if (clock_gettime(ust_clock_source, &ts) != 0) {
		ust_clock_source = CLOCK_MONOTONIC;
		DBG("UST traces will not be synchronized with LTTng traces");
	}

	autoprobe_val = getenv("UST_AUTOPROBE");
	if (autoprobe_val) {
		struct marker_iter iter;

		DBG("Autoprobe enabled.");

		/* Ensure markers are initialized */
		//init_markers();

		/* Ensure marker control is initialized, for the probe */
		init_marker_control();

		/* first, set the callback that will connect the
		 * probe on new markers
		 */
		if (autoprobe_val[0] == '/') {
			result = regcomp(&autoprobe_regex, autoprobe_val+1, 0);
			if (result) {
				char regexerr[150];

				regerror(result, &autoprobe_regex, regexerr, sizeof(regexerr));
				ERR("cannot parse regex %s (%s), will ignore UST_AUTOPROBE", autoprobe_val, regexerr);
				/* don't crash the application just for this */
			} else {
				autoprobe_method = AUTOPROBE_ENABLE_REGEX;
			}
		} else {
			/* just enable all instrumentation */
			autoprobe_method = AUTOPROBE_ENABLE_ALL;
		}

		marker_set_new_marker_cb(auto_probe_connect);

		/* Now, connect the probes that were already registered. */
		marker_iter_reset(&iter);
		marker_iter_start(&iter);

		DBG("now iterating on markers already registered");
		while (iter.marker) {
			DBG("now iterating on marker %s", (*iter.marker)->name);
			auto_probe_connect(*iter.marker);
			marker_iter_next(&iter);
		}
	}

	if (getenv("UST_OVERWRITE")) {
		int val = atoi(getenv("UST_OVERWRITE"));
		if (val == 0 || val == 1) {
			CMM_STORE_SHARED(ust_channels_overwrite_by_default, val);
		} else {
			WARN("invalid value for UST_OVERWRITE");
		}
	}

	if (getenv("UST_AUTOCOLLECT")) {
		int val = atoi(getenv("UST_AUTOCOLLECT"));
		if (val == 0 || val == 1) {
			CMM_STORE_SHARED(ust_channels_request_collection_by_default, val);
		} else {
			WARN("invalid value for UST_AUTOCOLLECT");
		}
	}

	subbuffer_size_val = getenv("UST_SUBBUF_SIZE");
	if (subbuffer_size_val) {
		sscanf(subbuffer_size_val, "%u", &subbuffer_size);
		power = pow2_higher_or_eq(subbuffer_size);
		if (power != subbuffer_size)
			WARN("using the next power of two for buffer size = %u\n", power);
		chan_infos[LTT_CHANNEL_UST].def_subbufsize = power;
	}

	subbuffer_count_val = getenv("UST_SUBBUF_NUM");
	if (subbuffer_count_val) {
		sscanf(subbuffer_count_val, "%u", &subbuffer_count);
		if (subbuffer_count < 2)
			subbuffer_count = 2;
		chan_infos[LTT_CHANNEL_UST].def_subbufcount = subbuffer_count;
	}

	if (getenv("UST_TRACE")) {
		char trace_name[] = "auto";
		char trace_type[] = "ustrelay";

		DBG("starting early tracing");

		/* Ensure marker control is initialized */
		init_marker_control();

		/* Ensure markers are initialized */
		init_markers();

		/* Ensure buffers are initialized, for the transport to be available.
		 * We are about to set a trace type and it will fail without this.
		 */
		init_ustrelay_transport();

		/* FIXME: When starting early tracing (here), depending on the
		 * order of constructors, it is very well possible some marker
		 * sections are not yet registered. Because of this, some
		 * channels may not be registered. Yet, we are about to ask the
		 * daemon to collect the channels. Channels which are not yet
		 * registered will not be collected.
		 *
		 * Currently, in LTTng, there is no way to add a channel after
		 * trace start. The reason for this is that it induces complex
		 * concurrency issues on the trace structures, which can only
		 * be resolved using RCU. This has not been done yet. As a
		 * workaround, we are forcing the registration of the "ust"
		 * channel here. This is the only channel (apart from metadata)
		 * that can be reliably used in early tracing.
		 *
		 * Non-early tracing does not have this problem and can use
		 * arbitrary channel names.
		 */
		ltt_channels_register("ust");

		result = ltt_trace_setup(trace_name);
		if (result < 0) {
			ERR("ltt_trace_setup failed");
			return;
		}

		result = ltt_trace_set_type(trace_name, trace_type);
		if (result < 0) {
			ERR("ltt_trace_set_type failed");
			return;
		}

		result = ltt_trace_alloc(trace_name);
		if (result < 0) {
			ERR("ltt_trace_alloc failed");
			return;
		}

		result = ltt_trace_start(trace_name);
		if (result < 0) {
			ERR("ltt_trace_start failed");
			return;
		}

		/* Do this after the trace is started in order to avoid creating confusion
		 * if the trace fails to start. */
		inform_consumer_daemon(trace_name);
	}

	return;

	/* should decrementally destroy stuff if error */

}

/* This is only called if we terminate normally, not with an unhandled signal,
 * so we cannot rely on it. However, for now, LTTV requires that the header of
 * the last sub-buffer contain a valid end time for the trace. This is done
 * automatically only when the trace is properly stopped.
 *
 * If the traced program crashed, it is always possible to manually add the
 * right value in the header, or to open the trace in text mode.
 *
 * FIXME: Fix LTTV so it doesn't need this.
 */

static void destroy_traces(void)
{
	int result;

	/* if trace running, finish it */

	DBG("destructor stopping traces");

	result = ltt_trace_stop("auto");
	if (result == -1) {
		ERR("ltt_trace_stop error");
	}

	result = ltt_trace_destroy("auto", 0);
	if (result == -1) {
		ERR("ltt_trace_destroy error");
	}
}

static int trace_recording(void)
{
	int retval = 0;
	struct ust_trace *trace;

	ltt_lock_traces();

	cds_list_for_each_entry(trace, &ltt_traces.head, list) {
		if (trace->active) {
			retval = 1;
			break;
		}
	}

	ltt_unlock_traces();

	return retval;
}

int restarting_usleep(useconds_t usecs)
{
        struct timespec tv;
        int result;

        tv.tv_sec = 0;
        tv.tv_nsec = usecs * 1000;

        do {
                result = nanosleep(&tv, &tv);
        } while (result == -1 && errno == EINTR);

	return result;
}

static void stop_listener(void)
{
	int result;

	if (!have_listener)
		return;

	result = pthread_cancel(listener_thread);
	if (result != 0) {
		ERR("pthread_cancel: %s", strerror(result));
	}
	result = pthread_join(listener_thread, NULL);
	if (result != 0) {
		ERR("pthread_join: %s", strerror(result));
	}
}

/* This destructor keeps the process alive for a few seconds in order
 * to leave time for ustconsumer to connect to its buffers. This is necessary
 * for programs whose execution is very short. It is also useful in all
 * programs when tracing is started close to the end of the program
 * execution.
 *
 * FIXME: For now, this only works for the first trace created in a
 * process.
 */

static void __attribute__((destructor)) keepalive()
{
	if (processpid != getpid()) {
		return;
	}

	if (trace_recording() && CMM_LOAD_SHARED(buffers_to_export)) {
		int total = 0;
		DBG("Keeping process alive for consumer daemon...");
		while (CMM_LOAD_SHARED(buffers_to_export)) {
			const int interv = 200000;
			restarting_usleep(interv);
			total += interv;

			if (total >= 3000000) {
				WARN("non-consumed buffers remaining after wait limit; not waiting anymore");
				break;
			}
		}
		DBG("Finally dying...");
	}

	destroy_traces();

	/* Ask the listener to stop and clean up. */
	stop_listener();
}

void ust_potential_exec(void)
{
	trace_mark(ust, potential_exec, MARK_NOARGS);

	DBG("test");

	keepalive();
}

/* Notify ust that there was a fork. This needs to be called inside
 * the new process, anytime a process whose memory is not shared with
 * the parent is created. If this function is not called, the events
 * of the new process will not be collected.
 *
 * Signals should be disabled before the fork and reenabled only after
 * this call in order to guarantee tracing is not started before ust_fork()
 * sanitizes the new process.
 */

static void ust_fork(void)
{
	struct ustcomm_sock *sock, *sock_tmp;
	struct ust_trace *trace, *trace_tmp;
	int result;

	/* FIXME: technically, the locks could have been taken before the fork */
	DBG("ust: forking");

	/* Get the pid of the new process */
	processpid = getpid();

	/*
	 * FIXME: This could be prettier, we loop over the list twice and
	 * following good locking practice should lock around the loop
	 */
	cds_list_for_each_entry_safe(trace, trace_tmp, &ltt_traces.head, list) {
		ltt_trace_stop(trace->trace_name);
	}

	/* Delete all active connections, but leave them in the epoll set */
	cds_list_for_each_entry_safe(sock, sock_tmp, &ust_socks, list) {
		ustcomm_del_sock(sock, 1);
	}

	/*
	 * FIXME: This could be prettier, we loop over the list twice and
	 * following good locking practice should lock around the loop
	 */
	cds_list_for_each_entry_safe(trace, trace_tmp, &ltt_traces.head, list) {
		ltt_trace_destroy(trace->trace_name, 1);
	}

	/* Clean up the listener socket and epoll, keeping the socket file */
	if (listen_sock) {
		ustcomm_del_named_sock(listen_sock, 1);
		listen_sock = NULL;
	}
	close(epoll_fd);

	/* Re-start the launch sequence */
	CMM_STORE_SHARED(buffers_to_export, 0);
	have_listener = 0;

	/* Set up epoll */
	epoll_fd = epoll_create(MAX_EVENTS);
	if (epoll_fd == -1) {
		ERR("epoll_create failed, tracing shutting down");
		return;
	}

	/* Create the socket */
	listen_sock = init_app_socket(epoll_fd);
	if (!listen_sock) {
		ERR("failed to create application socket,"
		    " tracing shutting down");
		return;
	}
	create_listener();
	ltt_trace_setup("auto");
	result = ltt_trace_set_type("auto", "ustrelay");
	if (result < 0) {
		ERR("ltt_trace_set_type failed");
		return;
	}

	ltt_trace_alloc("auto");
	ltt_trace_start("auto");
	inform_consumer_daemon("auto");
}

void ust_before_fork(ust_fork_info_t *fork_info)
{
        /* Disable signals. This is to avoid that the child
         * intervenes before it is properly setup for tracing. It is
         * safer to disable all signals, because then we know we are not
         * breaking anything by restoring the original mask.
         */
	sigset_t all_sigs;
	int result;

        /* FIXME:
                - only do this if tracing is active
        */

        /* Disable signals */
        sigfillset(&all_sigs);
        result = sigprocmask(SIG_BLOCK, &all_sigs, &fork_info->orig_sigs);
        if (result == -1) {
                PERROR("sigprocmask");
                return;
        }

	/*
	 * Take the fork lock to make sure we are not in the middle of
	 * something in the listener thread.
	 */
	pthread_mutex_lock(&listener_thread_data_mutex);
	/*
	 * Hold listen_sock_mutex to protect from listen_sock teardown.
	 */
	pthread_mutex_lock(&listen_sock_mutex);
	rcu_bp_before_fork();
}

/* Don't call this function directly in a traced program */
static void ust_after_fork_common(ust_fork_info_t *fork_info)
{
	int result;

	pthread_mutex_unlock(&listen_sock_mutex);
	pthread_mutex_unlock(&listener_thread_data_mutex);

        /* Restore signals */
        result = sigprocmask(SIG_SETMASK, &fork_info->orig_sigs, NULL);
        if (result == -1) {
                PERROR("sigprocmask");
                return;
        }
}

void ust_after_fork_parent(ust_fork_info_t *fork_info)
{
	rcu_bp_after_fork_parent();
	/* Release mutexes and reenable signals */
	ust_after_fork_common(fork_info);
}

void ust_after_fork_child(ust_fork_info_t *fork_info)
{
	/* Release urcu mutexes */
	rcu_bp_after_fork_child();

	/* Sanitize the child */
	ust_fork();

	/* Then release mutexes and reenable signals */
	ust_after_fork_common(fork_info);
}

