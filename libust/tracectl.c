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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <poll.h>
#include <regex.h>
#include <urcu/uatomic_arch.h>

#include <ust/marker.h>
#include <ust/tracepoint.h>
#include <ust/tracectl.h>
#include "tracer.h"
#include "usterr.h"
#include "ustcomm.h"
#include "buffers.h"
#include "marker-control.h"
#include "multipoll.h"

#define USTSIGNAL SIGIO

#define MAX_MSG_SIZE (100)
#define MSG_NOTIF 1
#define MSG_REGISTER_NOTIF 2

/* This should only be accessed by the constructor, before the creation
 * of the listener, and then only by the listener.
 */
s64 pidunique = -1LL;

extern struct chan_info_struct chan_infos[];

struct list_head blocked_consumers = LIST_HEAD_INIT(blocked_consumers);

static struct ustcomm_app ustcomm_app;

struct tracecmd { /* no padding */
	uint32_t size;
	uint16_t command;
};

/* volatile because shared between the listener and the main thread */
int buffers_to_export = 0;

struct trctl_msg {
	/* size: the size of all the fields except size itself */
	uint32_t size;
	uint16_t type;
	/* Only the necessary part of the payload is transferred. It
         * may even be none of it.
         */
	char payload[94];
};

struct consumer_channel {
	int fd;
	struct ltt_channel_struct *chan;
};

struct blocked_consumer {
	int fd_consumer;
	int fd_producer;
	int tmp_poll_idx;

	/* args to ustcomm_send_reply */
	struct ustcomm_server server;
	struct ustcomm_source src;

	/* args to ust_buffers_get_subbuf */
	struct ust_buffer *buf;

	struct list_head list;
};

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

	while(iter.marker) {
		fprintf(fp, "marker: %s/%s %d \"%s\" %p\n", iter.marker->channel, iter.marker->name, (int)imv_read(iter.marker->state), iter.marker->format, iter.marker->location);
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

	while(iter.trace_event) {
		fprintf(fp, "trace_event: %s\n", iter.trace_event->name);
		trace_event_iter_next(&iter);
	}
	unlock_trace_events();
}

static int init_socket(void);

/* Ask the daemon to collect a trace called trace_name and being
 * produced by this pid.
 *
 * The trace must be at least allocated. (It can also be started.)
 * This is because _ltt_trace_find is used.
 */

static void inform_consumer_daemon(const char *trace_name)
{
	int i,j;
	struct ust_trace *trace;
	pid_t pid = getpid();
	int result;

	ltt_lock_traces();

	trace = _ltt_trace_find(trace_name);
	if(trace == NULL) {
		WARN("inform_consumer_daemon: could not find trace \"%s\"; it is probably already destroyed", trace_name);
		goto finish;
	}

	for(i=0; i < trace->nr_channels; i++) {
		if(trace->channels[i].request_collection) {
			/* iterate on all cpus */
			for(j=0; j<trace->channels[i].n_cpus; j++) {
				char *buf;
				if (asprintf(&buf, "%s_%d", trace->channels[i].channel_name, j) < 0) {
                                       ERR("inform_consumer_daemon : asprintf failed (%s_%d)",
					   trace->channels[i].channel_name, j);
                                       goto finish;
				}
				result = ustcomm_request_consumer(pid, buf);
				if(result == -1) {
					WARN("Failed to request collection for channel %s. Is the daemon available?", trace->channels[i].channel_name);
					/* continue even if fail */
				}
				free(buf);
				STORE_SHARED(buffers_to_export, LOAD_SHARED(buffers_to_export)+1);
			}
		}
	}

	finish:
	ltt_unlock_traces();
}

int process_blkd_consumer_act(void *priv, int fd, short events)
{
	int result;
	long consumed_old = 0;
	char *reply;
	struct blocked_consumer *bc = (struct blocked_consumer *) priv;
	char inbuf;

	result = read(bc->fd_producer, &inbuf, 1);
	if(result == -1) {
		PERROR("read");
		return -1;
	}
	if(result == 0) {
		int res;
		DBG("listener: got messsage that a buffer ended");

		res = close(bc->fd_producer);
		if(res == -1) {
			PERROR("close");
		}

		list_del(&bc->list);

		result = ustcomm_send_reply(&bc->server, "END", &bc->src);
		if(result < 0) {
			ERR("ustcomm_send_reply failed");
			return -1;
		}

		return 0;
	}

	result = ust_buffers_get_subbuf(bc->buf, &consumed_old);
	if(result == -EAGAIN) {
		WARN("missed buffer?");
		return 0;
	}
	else if(result < 0) {
		ERR("ust_buffers_get_subbuf: error: %s", strerror(-result));
	}
	if (asprintf(&reply, "%s %ld", "OK", consumed_old) < 0) {
               ERR("process_blkd_consumer_act : asprintf failed (OK %ld)",
		   consumed_old);
               return -1;
	}
	result = ustcomm_send_reply(&bc->server, reply, &bc->src);
	if(result < 0) {
		ERR("ustcomm_send_reply failed");
		free(reply);
		return -1;
	}
	free(reply);

	list_del(&bc->list);

	return 0;
}

void blocked_consumers_add_to_mp(struct mpentries *ent)
{
	struct blocked_consumer *bc;

	list_for_each_entry(bc, &blocked_consumers, list) {
		multipoll_add(ent, bc->fd_producer, POLLIN, process_blkd_consumer_act, bc, NULL);
	}

}

void seperate_channel_cpu(const char *channel_and_cpu, char **channel, int *cpu)
{
	const char *sep;

	sep = rindex(channel_and_cpu, '_');
	if(sep == NULL) {
		*cpu = -1;
		sep = channel_and_cpu + strlen(channel_and_cpu);
	}
	else {
		*cpu = atoi(sep+1);
	}

	if (asprintf(channel, "%.*s", (int)(sep-channel_and_cpu), channel_and_cpu) < 0) {
		ERR("seperate_channel_cpu : asprintf failed (%.*s)",
		    (int)(sep-channel_and_cpu), channel_and_cpu);
		return;
	}
}

static int do_cmd_get_shmid(const char *recvbuf, struct ustcomm_source *src)
{
	int retval = 0;
	struct ust_trace *trace;
	char trace_name[] = "auto";
	int i;
	char *channel_and_cpu;
	int found = 0;
	int result;
	char *ch_name;
	int ch_cpu;

	DBG("get_shmid");

	channel_and_cpu = nth_token(recvbuf, 1);
	if(channel_and_cpu == NULL) {
		ERR("cannot parse channel");
		retval = -1;
		goto end;
	}

	seperate_channel_cpu(channel_and_cpu, &ch_name, &ch_cpu);
	if(ch_cpu == -1) {
		ERR("problem parsing channel name");
		retval = -1;
		goto free_short_chan_name;
	}

	ltt_lock_traces();
	trace = _ltt_trace_find(trace_name);
	ltt_unlock_traces();

	if(trace == NULL) {
		ERR("cannot find trace!");
		retval = -1;
		goto free_short_chan_name;
	}

	for(i=0; i<trace->nr_channels; i++) {
		struct ust_channel *channel = &trace->channels[i];
		struct ust_buffer *buf = channel->buf[ch_cpu];

		if(!strcmp(trace->channels[i].channel_name, ch_name)) {
			char *reply;

//			DBG("the shmid for the requested channel is %d", buf->shmid);
//			DBG("the shmid for its buffer structure is %d", channel->buf_struct_shmids);
			if (asprintf(&reply, "%d %d", buf->shmid, channel->buf_struct_shmids[ch_cpu]) < 0) {
				ERR("do_cmd_get_shmid : asprintf failed (%d %d)",
				    buf->shmid, channel->buf_struct_shmids[ch_cpu]);
				retval = -1;
				goto free_short_chan_name;
			}

			result = ustcomm_send_reply(&ustcomm_app.server, reply, src);
			if(result) {
				ERR("ustcomm_send_reply failed");
				free(reply);
				retval = -1;
				goto free_short_chan_name;
			}

			free(reply);

			found = 1;
			break;
		}
	}

	if(!found) {
		ERR("channel not found (%s)", channel_and_cpu);
	}

	free_short_chan_name:
	free(ch_name);

	end:
	return retval;
}

static int do_cmd_get_n_subbufs(const char *recvbuf, struct ustcomm_source *src)
{
	int retval = 0;
	struct ust_trace *trace;
	char trace_name[] = "auto";
	int i;
	char *channel_and_cpu;
	int found = 0;
	int result;
	char *ch_name;
	int ch_cpu;

	DBG("get_n_subbufs");

	channel_and_cpu = nth_token(recvbuf, 1);
	if(channel_and_cpu == NULL) {
		ERR("cannot parse channel");
		retval = -1;
		goto end;
	}

	seperate_channel_cpu(channel_and_cpu, &ch_name, &ch_cpu);
	if(ch_cpu == -1) {
		ERR("problem parsing channel name");
		retval = -1;
		goto free_short_chan_name;
	}

	ltt_lock_traces();
	trace = _ltt_trace_find(trace_name);
	ltt_unlock_traces();

	if(trace == NULL) {
		ERR("cannot find trace!");
		retval = -1;
		goto free_short_chan_name;
	}

	for(i=0; i<trace->nr_channels; i++) {
		struct ust_channel *channel = &trace->channels[i];

		if(!strcmp(trace->channels[i].channel_name, ch_name)) {
			char *reply;

			DBG("the n_subbufs for the requested channel is %d", channel->subbuf_cnt);
			if (asprintf(&reply, "%d", channel->subbuf_cnt) < 0) {
				ERR("do_cmd_get_n_subbufs : asprintf failed (%d)",
				    channel->subbuf_cnt);
				retval = -1;
				goto free_short_chan_name;
			}

			result = ustcomm_send_reply(&ustcomm_app.server, reply, src);
			if(result) {
				ERR("ustcomm_send_reply failed");
				free(reply);
				retval = -1;
				goto free_short_chan_name;
			}

			free(reply);
			found = 1;
			break;
		}
	}
	if(found == 0) {
		ERR("unable to find channel");
	}

	free_short_chan_name:
	free(ch_name);

	end:
	return retval;
}

static int do_cmd_get_subbuf_size(const char *recvbuf, struct ustcomm_source *src)
{
	int retval = 0;
	struct ust_trace *trace;
	char trace_name[] = "auto";
	int i;
	char *channel_and_cpu;
	int found = 0;
	int result;
	char *ch_name;
	int ch_cpu;

	DBG("get_subbuf_size");

	channel_and_cpu = nth_token(recvbuf, 1);
	if(channel_and_cpu == NULL) {
		ERR("cannot parse channel");
		retval = -1;
		goto end;
	}

	seperate_channel_cpu(channel_and_cpu, &ch_name, &ch_cpu);
	if(ch_cpu == -1) {
		ERR("problem parsing channel name");
		retval = -1;
		goto free_short_chan_name;
	}

	ltt_lock_traces();
	trace = _ltt_trace_find(trace_name);
	ltt_unlock_traces();

	if(trace == NULL) {
		ERR("cannot find trace!");
		retval = -1;
		goto free_short_chan_name;
	}

	for(i=0; i<trace->nr_channels; i++) {
		struct ust_channel *channel = &trace->channels[i];

		if(!strcmp(trace->channels[i].channel_name, ch_name)) {
			char *reply;

			DBG("the subbuf_size for the requested channel is %zd", channel->subbuf_size);
			if (asprintf(&reply, "%zd", channel->subbuf_size) < 0) {
				ERR("do_cmd_get_subbuf_size : asprintf failed (%zd)",
				    channel->subbuf_size);
				retval = -1;
				goto free_short_chan_name;
			}

			result = ustcomm_send_reply(&ustcomm_app.server, reply, src);
			if(result) {
				ERR("ustcomm_send_reply failed");
				free(reply);
				retval = -1;
				goto free_short_chan_name;
			}

			free(reply);
			found = 1;
			break;
		}
	}
	if(found == 0) {
		ERR("unable to find channel");
	}

	free_short_chan_name:
	free(ch_name);

	end:
	return retval;
}

/* Return the power of two which is equal or higher to v */

static unsigned int pow2_higher_or_eq(unsigned int v)
{
	int hb = fls(v);
	int retval = 1<<(hb-1);

	if(v-retval == 0)
		return retval;
	else
		return retval<<1;
}

static int do_cmd_set_subbuf_size(const char *recvbuf, struct ustcomm_source *src)
{
	char *channel_slash_size;
	char ch_name[256]="";
	unsigned int size, power;
	int retval = 0;
	struct ust_trace *trace;
	char trace_name[] = "auto";
	int i;
	int found = 0;

	DBG("set_subbuf_size");

	channel_slash_size = nth_token(recvbuf, 1);
	sscanf(channel_slash_size, "%255[^/]/%u", ch_name, &size);

	if(ch_name == NULL) {
		ERR("cannot parse channel");
		retval = -1;
		goto end;
	}

	power = pow2_higher_or_eq(size);
	power = max_t(unsigned int, 2u, power);
	if (power != size)
		WARN("using the next power of two for buffer size = %u\n", power);

	ltt_lock_traces();
	trace = _ltt_trace_find_setup(trace_name);
	if(trace == NULL) {
		ERR("cannot find trace!");
		retval = -1;
		goto end;
	}

	for(i = 0; i < trace->nr_channels; i++) {
		struct ust_channel *channel = &trace->channels[i];

		if(!strcmp(trace->channels[i].channel_name, ch_name)) {

			channel->subbuf_size = power;
			DBG("the set_subbuf_size for the requested channel is %zd", channel->subbuf_size);

			found = 1;
			break;
		}
	}
	if(found == 0) {
		ERR("unable to find channel");
	}

	end:
	ltt_unlock_traces();
	return retval;
}

static int do_cmd_set_subbuf_num(const char *recvbuf, struct ustcomm_source *src)
{
	char *channel_slash_num;
	char ch_name[256]="";
	unsigned int num;
	int retval = 0;
	struct ust_trace *trace;
	char trace_name[] = "auto";
	int i;
	int found = 0;

	DBG("set_subbuf_num");

	channel_slash_num = nth_token(recvbuf, 1);
	sscanf(channel_slash_num, "%255[^/]/%u", ch_name, &num);

	if(ch_name == NULL) {
		ERR("cannot parse channel");
		retval = -1;
		goto end;
	}
	if (num < 2) {
		ERR("subbuffer count should be greater than 2");
		retval = -1;
		goto end;
	}

	ltt_lock_traces();
	trace = _ltt_trace_find_setup(trace_name);
	if(trace == NULL) {
		ERR("cannot find trace!");
		retval = -1;
		goto end;
	}

	for(i = 0; i < trace->nr_channels; i++) {
		struct ust_channel *channel = &trace->channels[i];

		if(!strcmp(trace->channels[i].channel_name, ch_name)) {

			channel->subbuf_cnt = num;
			DBG("the set_subbuf_cnt for the requested channel is %zd", channel->subbuf_cnt);

			found = 1;
			break;
		}
	}
	if(found == 0) {
		ERR("unable to find channel");
	}

	end:
	ltt_unlock_traces();
	return retval;
}

static int do_cmd_get_subbuffer(const char *recvbuf, struct ustcomm_source *src)
{
	int retval = 0;
	struct ust_trace *trace;
	char trace_name[] = "auto";
	int i;
	char *channel_and_cpu;
	int found = 0;
	char *ch_name;
	int ch_cpu;

	DBG("get_subbuf");

	channel_and_cpu = nth_token(recvbuf, 1);
	if(channel_and_cpu == NULL) {
		ERR("cannot parse channel");
		retval = -1;
		goto end;
	}

	seperate_channel_cpu(channel_and_cpu, &ch_name, &ch_cpu);
	if(ch_cpu == -1) {
		ERR("problem parsing channel name");
		retval = -1;
		goto free_short_chan_name;
	}

	ltt_lock_traces();
	trace = _ltt_trace_find(trace_name);

	if(trace == NULL) {
		int result;

		DBG("Cannot find trace. It was likely destroyed by the user.");
		result = ustcomm_send_reply(&ustcomm_app.server, "NOTFOUND", src);
		if(result) {
			ERR("ustcomm_send_reply failed");
			retval = -1;
			goto unlock_traces;
		}

		goto unlock_traces;
	}

	for(i=0; i<trace->nr_channels; i++) {
		struct ust_channel *channel = &trace->channels[i];

		if(!strcmp(trace->channels[i].channel_name, ch_name)) {
			struct ust_buffer *buf = channel->buf[ch_cpu];
			struct blocked_consumer *bc;

			found = 1;

			bc = (struct blocked_consumer *) zmalloc(sizeof(struct blocked_consumer));
			if(bc == NULL) {
				ERR("zmalloc returned NULL");
				goto unlock_traces;
			}
			bc->fd_consumer = src->fd;
			bc->fd_producer = buf->data_ready_fd_read;
			bc->buf = buf;
			bc->src = *src;
			bc->server = ustcomm_app.server;

			list_add(&bc->list, &blocked_consumers);

			/* Being here is the proof the daemon has mapped the buffer in its
			 * memory. We may now decrement buffers_to_export.
			 */
			if(uatomic_read(&buf->consumed) == 0) {
				DBG("decrementing buffers_to_export");
				STORE_SHARED(buffers_to_export, LOAD_SHARED(buffers_to_export)-1);
			}

			break;
		}
	}
	if(found == 0) {
		ERR("unable to find channel");
	}

	unlock_traces:
	ltt_unlock_traces();

	free_short_chan_name:
	free(ch_name);

	end:
	return retval;
}

static int do_cmd_put_subbuffer(const char *recvbuf, struct ustcomm_source *src)
{
	int retval = 0;
	struct ust_trace *trace;
	char trace_name[] = "auto";
	int i;
	char *channel_and_cpu;
	int found = 0;
	int result;
	char *ch_name;
	int ch_cpu;
	long consumed_old;
	char *consumed_old_str;
	char *endptr;
	char *reply = NULL;

	DBG("put_subbuf");

	channel_and_cpu = strdup(nth_token(recvbuf, 1));
	if(channel_and_cpu == NULL) {
		ERR("cannot parse channel");
		retval = -1;
		goto end;
	}

	consumed_old_str = strdup(nth_token(recvbuf, 2));
	if(consumed_old_str == NULL) {
		ERR("cannot parse consumed_old");
		retval = -1;
		goto free_channel_and_cpu;
	}
	consumed_old = strtol(consumed_old_str, &endptr, 10);
	if(*endptr != '\0') {
		ERR("invalid value for consumed_old");
		retval = -1;
		goto free_consumed_old_str;
	}

	seperate_channel_cpu(channel_and_cpu, &ch_name, &ch_cpu);
	if(ch_cpu == -1) {
		ERR("problem parsing channel name");
		retval = -1;
		goto free_short_chan_name;
	}

	ltt_lock_traces();
	trace = _ltt_trace_find(trace_name);

	if(trace == NULL) {
		DBG("Cannot find trace. It was likely destroyed by the user.");
		result = ustcomm_send_reply(&ustcomm_app.server, "NOTFOUND", src);
		if(result) {
			ERR("ustcomm_send_reply failed");
			retval = -1;
			goto unlock_traces;
		}

		goto unlock_traces;
	}

	for(i=0; i<trace->nr_channels; i++) {
		struct ust_channel *channel = &trace->channels[i];

		if(!strcmp(trace->channels[i].channel_name, ch_name)) {
			struct ust_buffer *buf = channel->buf[ch_cpu];

			found = 1;

			result = ust_buffers_put_subbuf(buf, consumed_old);
			if(result < 0) {
				WARN("ust_buffers_put_subbuf: error (subbuf=%s)", channel_and_cpu);
				if (asprintf(&reply, "%s", "ERROR") < 0) {
					ERR("do_cmd_put_subbuffer : asprintf failed (ERROR)");
					retval = -1;
					goto unlock_traces;
				}
			}
			else {
				DBG("ust_buffers_put_subbuf: success (subbuf=%s)", channel_and_cpu);
				if (asprintf(&reply, "%s", "OK") < 0) {
					ERR("do_cmd_put_subbuffer : asprintf failed (OK)");
					retval = -1;
					goto unlock_traces;
				}
			}

			result = ustcomm_send_reply(&ustcomm_app.server, reply, src);
			if(result) {
				ERR("ustcomm_send_reply failed");
				free(reply);
				retval = -1;
				goto unlock_traces;
			}

			free(reply);
			break;
		}
	}
	if(found == 0) {
		ERR("unable to find channel");
	}

	unlock_traces:
	ltt_unlock_traces();
	free_short_chan_name:
	free(ch_name);
	free_consumed_old_str:
	free(consumed_old_str);
	free_channel_and_cpu:
	free(channel_and_cpu);

	end:
	return retval;
}

static void listener_cleanup(void *ptr)
{
	ustcomm_fini_app(&ustcomm_app, 0);
}

static void do_cmd_force_switch()
{
	struct blocked_consumer *bc;

	list_for_each_entry(bc, &blocked_consumers, list) {
		ltt_force_switch(bc->buf, FORCE_FLUSH);
	}
}

int process_client_cmd(char *recvbuf, struct ustcomm_source *src)
{
	int result;
	char trace_name[] = "auto";
	char trace_type[] = "ustrelay";
	int len;

	DBG("received a message! it's: %s", recvbuf);
	len = strlen(recvbuf);

	if(!strcmp(recvbuf, "print_markers")) {
		print_markers(stderr);
	}
	else if(!strcmp(recvbuf, "list_markers")) {
		char *ptr;
		size_t size;
		FILE *fp;

		fp = open_memstream(&ptr, &size);
		print_markers(fp);
		fclose(fp);

		result = ustcomm_send_reply(&ustcomm_app.server, ptr, src);

		free(ptr);
	} else if (!strcmp(recvbuf, "print_trace_events")) {
		print_trace_events(stderr);

	} else if(!strcmp(recvbuf, "list_trace_events")) {
		char *ptr;
		size_t size;
		FILE *fp;

		fp = open_memstream(&ptr, &size);
		if (fp == NULL) {
			ERR("opening memstream failed");
			return -1;
		}
		print_trace_events(fp);
		fclose(fp);

		result = ustcomm_send_reply(&ustcomm_app.server, ptr, src);
		if (result < 0) {
			ERR("list_trace_events failed");
			return -1;
		}
		free(ptr);
	} else if(!strcmp(recvbuf, "start")) {
		/* start is an operation that setups the trace, allocates it and starts it */
		result = ltt_trace_setup(trace_name);
		if(result < 0) {
			ERR("ltt_trace_setup failed");
			return -1;
		}

		result = ltt_trace_set_type(trace_name, trace_type);
		if(result < 0) {
			ERR("ltt_trace_set_type failed");
			return -1;
		}

		result = ltt_trace_alloc(trace_name);
		if(result < 0) {
			ERR("ltt_trace_alloc failed");
			return -1;
		}

		inform_consumer_daemon(trace_name);

		result = ltt_trace_start(trace_name);
		if(result < 0) {
			ERR("ltt_trace_start failed");
			return -1;
		}
	}
	else if(!strcmp(recvbuf, "trace_setup")) {
		DBG("trace setup");

		result = ltt_trace_setup(trace_name);
		if(result < 0) {
			ERR("ltt_trace_setup failed");
			return -1;
		}

		result = ltt_trace_set_type(trace_name, trace_type);
		if(result < 0) {
			ERR("ltt_trace_set_type failed");
			return -1;
		}
	}
	else if(!strcmp(recvbuf, "trace_alloc")) {
		DBG("trace alloc");

		result = ltt_trace_alloc(trace_name);
		if(result < 0) {
			ERR("ltt_trace_alloc failed");
			return -1;
		}
		inform_consumer_daemon(trace_name);
	}
	else if(!strcmp(recvbuf, "trace_create")) {
		DBG("trace create");

		result = ltt_trace_setup(trace_name);
		if(result < 0) {
			ERR("ltt_trace_setup failed");
			return -1;
		}

		result = ltt_trace_set_type(trace_name, trace_type);
		if(result < 0) {
			ERR("ltt_trace_set_type failed");
			return -1;
		}
	}
	else if(!strcmp(recvbuf, "trace_start")) {
		DBG("trace start");

		result = ltt_trace_alloc(trace_name);
		if(result < 0) {
			ERR("ltt_trace_alloc failed");
			return -1;
		}
		if(!result) {
			inform_consumer_daemon(trace_name);
		}

		result = ltt_trace_start(trace_name);
		if(result < 0) {
			ERR("ltt_trace_start failed");
			return -1;
		}
	}
	else if(!strcmp(recvbuf, "trace_stop")) {
		DBG("trace stop");

		result = ltt_trace_stop(trace_name);
		if(result < 0) {
			ERR("ltt_trace_stop failed");
			return -1;
		}
	}
	else if(!strcmp(recvbuf, "trace_destroy")) {

		DBG("trace destroy");

		result = ltt_trace_destroy(trace_name, 0);
		if(result < 0) {
			ERR("ltt_trace_destroy failed");
			return -1;
		}
	}
	else if(nth_token_is(recvbuf, "get_shmid", 0) == 1) {
		do_cmd_get_shmid(recvbuf, src);
	}
	else if(nth_token_is(recvbuf, "get_n_subbufs", 0) == 1) {
		do_cmd_get_n_subbufs(recvbuf, src);
	}
	else if(nth_token_is(recvbuf, "get_subbuf_size", 0) == 1) {
		do_cmd_get_subbuf_size(recvbuf, src);
	}
	else if(nth_token_is(recvbuf, "load_probe_lib", 0) == 1) {
		char *libfile;

		libfile = nth_token(recvbuf, 1);

		DBG("load_probe_lib loading %s", libfile);

		free(libfile);
	}
	else if(nth_token_is(recvbuf, "get_subbuffer", 0) == 1) {
		do_cmd_get_subbuffer(recvbuf, src);
	}
	else if(nth_token_is(recvbuf, "put_subbuffer", 0) == 1) {
		do_cmd_put_subbuffer(recvbuf, src);
	}
	else if(nth_token_is(recvbuf, "set_subbuf_size", 0) == 1) {
		do_cmd_set_subbuf_size(recvbuf, src);
	}
	else if(nth_token_is(recvbuf, "set_subbuf_num", 0) == 1) {
		do_cmd_set_subbuf_num(recvbuf, src);
	}
	else if(nth_token_is(recvbuf, "enable_marker", 0) == 1) {
		char *channel_slash_name = nth_token(recvbuf, 1);
		char channel_name[256]="";
		char marker_name[256]="";

		result = sscanf(channel_slash_name, "%255[^/]/%255s", channel_name, marker_name);

		if(channel_name == NULL || marker_name == NULL) {
			WARN("invalid marker name");
			goto next_cmd;
		}

		result = ltt_marker_connect(channel_name, marker_name, "default");
		if(result < 0) {
			WARN("could not enable marker; channel=%s, name=%s", channel_name, marker_name);
		}
	}
	else if(nth_token_is(recvbuf, "disable_marker", 0) == 1) {
		char *channel_slash_name = nth_token(recvbuf, 1);
		char *marker_name;
		char *channel_name;

		result = sscanf(channel_slash_name, "%a[^/]/%as", &channel_name, &marker_name);

		if(marker_name == NULL) {
		}

		result = ltt_marker_disconnect(channel_name, marker_name, "default");
		if(result < 0) {
			WARN("could not disable marker; channel=%s, name=%s", channel_name, marker_name);
		}
	}
	else if(nth_token_is(recvbuf, "get_pidunique", 0) == 1) {
		char *reply;

		if (asprintf(&reply, "%lld", pidunique) < 0) {
			ERR("process_client_cmd : asprintf failed (%lld)",
			    pidunique);
			goto next_cmd;
		}

		result = ustcomm_send_reply(&ustcomm_app.server, reply, src);
		if(result) {
			ERR("listener: get_pidunique: ustcomm_send_reply failed");
			goto next_cmd;
		}

		free(reply);
	}
	else if(nth_token_is(recvbuf, "get_sock_path", 0) == 1) {
		char *reply = getenv("UST_DAEMON_SOCKET");
		if(!reply) {
			if (asprintf(&reply, "%s/%s", SOCK_DIR, "ustd") < 0) {
				ERR("process_client_cmd : asprintf failed (%s/ustd)",
				    SOCK_DIR);
				goto next_cmd;
			}
			result = ustcomm_send_reply(&ustcomm_app.server, reply, src);
			free(reply);
		}
		else {
			result = ustcomm_send_reply(&ustcomm_app.server, reply, src);
		}
		if(result)
			ERR("ustcomm_send_reply failed");
	}
	else if(nth_token_is(recvbuf, "set_sock_path", 0) == 1) {
		char *sock_path = nth_token(recvbuf, 1);
		result = setenv("UST_DAEMON_SOCKET", sock_path, 1);
		if(result)
			ERR("cannot set UST_DAEMON_SOCKET environment variable");
	}
	else if(nth_token_is(recvbuf, "force_switch", 0) == 1) {
		do_cmd_force_switch();
	}
	else {
		ERR("unable to parse message: %s", recvbuf);
	}

next_cmd:

	return 0;
}

void *listener_main(void *p)
{
	int result;

	DBG("LISTENER");

	pthread_cleanup_push(listener_cleanup, NULL);

	for(;;) {
		struct mpentries mpent;

		multipoll_init(&mpent);

		blocked_consumers_add_to_mp(&mpent);
		ustcomm_mp_add_app_clients(&mpent, &ustcomm_app, process_client_cmd);

		result = multipoll_poll(&mpent, -1);
		if(result == -1) {
			ERR("error in multipoll_poll");
		}

		multipoll_destroy(&mpent);
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

	if(have_listener) {
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
	if(result) {
		PERROR("pthread_sigmask: %s", strerror(result));
	}

	result = pthread_create(&listener_thread, NULL, listener_main, NULL);
	if(result == -1) {
		PERROR("pthread_create");
	}

	/* Restore original signal mask in parent */
	result = pthread_sigmask(SIG_SETMASK, &orig_parent_mask, NULL);
	if(result) {
		PERROR("pthread_sigmask: %s", strerror(result));
	}
	else {
		have_listener = 1;
	}
}

static int init_socket(void)
{
	return ustcomm_init_app(getpid(), &ustcomm_app);
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

	if(autoprobe_method == AUTOPROBE_DISABLED) {
		return;
	}
	else if(autoprobe_method == AUTOPROBE_ENABLE_REGEX) {
		result = asprintf(&concat_name, "%s/%s", m->channel, m->name);
		if(result == -1) {
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
	if(result && result != -EEXIST)
		ERR("ltt_marker_connect (marker = %s/%s, errno = %d)", m->channel, m->name, -result);

	DBG("auto connected marker %s (addr: %p) %s to probe default", m->channel, m, m->name);

}

static void __attribute__((constructor)) init()
{
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

	DBG("Tracectl constructor");

	result = init_socket();
	if(result == -1) {
		ERR("init_socket error");
		return;
	}

	create_listener();

	autoprobe_val = getenv("UST_AUTOPROBE");
	if(autoprobe_val) {
		struct marker_iter iter;

		DBG("Autoprobe enabled.");

		/* Ensure markers are initialized */
		//init_markers();

		/* Ensure marker control is initialized, for the probe */
		init_marker_control();

		/* first, set the callback that will connect the
		 * probe on new markers
		 */
		if(autoprobe_val[0] == '/') {
			result = regcomp(&autoprobe_regex, autoprobe_val+1, 0);
			if (result) {
				char regexerr[150];

				regerror(result, &autoprobe_regex, regexerr, sizeof(regexerr));
				ERR("cannot parse regex %s (%s), will ignore UST_AUTOPROBE", autoprobe_val, regexerr);
				/* don't crash the application just for this */
			}
			else {
				autoprobe_method = AUTOPROBE_ENABLE_REGEX;
			}
		}
		else {
			/* just enable all instrumentation */
			autoprobe_method = AUTOPROBE_ENABLE_ALL;
		}

		marker_set_new_marker_cb(auto_probe_connect);

		/* Now, connect the probes that were already registered. */
		marker_iter_reset(&iter);
		marker_iter_start(&iter);

		DBG("now iterating on markers already registered");
		while(iter.marker) {
			DBG("now iterating on marker %s", iter.marker->name);
			auto_probe_connect(iter.marker);
			marker_iter_next(&iter);
		}
	}

	if(getenv("UST_OVERWRITE")) {
		int val = atoi(getenv("UST_OVERWRITE"));
		if(val == 0 || val == 1) {
			STORE_SHARED(ust_channels_overwrite_by_default, val);
		}
		else {
			WARN("invalid value for UST_OVERWRITE");
		}
	}

	if(getenv("UST_AUTOCOLLECT")) {
		int val = atoi(getenv("UST_AUTOCOLLECT"));
		if(val == 0 || val == 1) {
			STORE_SHARED(ust_channels_request_collection_by_default, val);
		}
		else {
			WARN("invalid value for UST_AUTOCOLLECT");
		}
	}

	subbuffer_size_val = getenv("UST_SUBBUF_SIZE");
	if(subbuffer_size_val) {
		sscanf(subbuffer_size_val, "%u", &subbuffer_size);
		power = pow2_higher_or_eq(subbuffer_size);
		if(power != subbuffer_size)
			WARN("using the next power of two for buffer size = %u\n", power);
		chan_infos[LTT_CHANNEL_UST].def_subbufsize = power;
	}

	subbuffer_count_val = getenv("UST_SUBBUF_NUM");
	if(subbuffer_count_val) {
		sscanf(subbuffer_count_val, "%u", &subbuffer_count);
		if(subbuffer_count < 2)
			subbuffer_count = 2;
		chan_infos[LTT_CHANNEL_UST].def_subbufcount = subbuffer_count;
	}

	if(getenv("UST_TRACE")) {
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
		if(result < 0) {
			ERR("ltt_trace_setup failed");
			return;
		}

		result = ltt_trace_set_type(trace_name, trace_type);
		if(result < 0) {
			ERR("ltt_trace_set_type failed");
			return;
		}

		result = ltt_trace_alloc(trace_name);
		if(result < 0) {
			ERR("ltt_trace_alloc failed");
			return;
		}

		result = ltt_trace_start(trace_name);
		if(result < 0) {
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
	if(result == -1) {
		ERR("ltt_trace_stop error");
	}

	result = ltt_trace_destroy("auto", 0);
	if(result == -1) {
		ERR("ltt_trace_destroy error");
	}
}

static int trace_recording(void)
{
	int retval = 0;
	struct ust_trace *trace;

	ltt_lock_traces();

	list_for_each_entry(trace, &ltt_traces.head, list) {
		if(trace->active) {
			retval = 1;
			break;
		}
	}

	ltt_unlock_traces();

	return retval;
}

#if 0
static int have_consumer(void)
{
	return !list_empty(&blocked_consumers);
}
#endif

int restarting_usleep(useconds_t usecs)
{
        struct timespec tv; 
        int result; 
 
        tv.tv_sec = 0; 
        tv.tv_nsec = usecs * 1000; 
 
        do { 
                result = nanosleep(&tv, &tv); 
        } while(result == -1 && errno == EINTR); 

	return result;
}

static void stop_listener(void)
{
	int result;

	if(!have_listener)
		return;

	result = pthread_cancel(listener_thread);
	if(result != 0) {
		ERR("pthread_cancel: %s", strerror(result));
	}
	result = pthread_join(listener_thread, NULL);
	if(result != 0) {
		ERR("pthread_join: %s", strerror(result));
	}
}

/* This destructor keeps the process alive for a few seconds in order
 * to leave time to ustd to connect to its buffers. This is necessary
 * for programs whose execution is very short. It is also useful in all
 * programs when tracing is started close to the end of the program
 * execution.
 *
 * FIXME: For now, this only works for the first trace created in a
 * process.
 */

static void __attribute__((destructor)) keepalive()
{
	if(trace_recording() && LOAD_SHARED(buffers_to_export)) {
		int total = 0;
		DBG("Keeping process alive for consumer daemon...");
		while(LOAD_SHARED(buffers_to_export)) {
			const int interv = 200000;
			restarting_usleep(interv);
			total += interv;

			if(total >= 3000000) {
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
	struct blocked_consumer *bc;
	struct blocked_consumer *deletable_bc = NULL;
	int result;

	/* FIXME: technically, the locks could have been taken before the fork */
	DBG("ust: forking");

	/* break lock if necessary */
	ltt_unlock_traces();

	ltt_trace_stop("auto");
	ltt_trace_destroy("auto", 1);
	/* Delete all active connections */
	ustcomm_close_all_connections(&ustcomm_app.server);

	/* Delete all blocked consumers */
	list_for_each_entry(bc, &blocked_consumers, list) {
		result = close(bc->fd_producer);
		if(result == -1) {
			PERROR("close");
		}
		free(deletable_bc);
		deletable_bc = bc;
		list_del(&bc->list);
	}

	/* free app, keeping socket file */
	ustcomm_fini_app(&ustcomm_app, 1);

	STORE_SHARED(buffers_to_export, 0);
	have_listener = 0;
	init_socket();
	create_listener();
	ltt_trace_setup("auto");
	result = ltt_trace_set_type("auto", "ustrelay");
	if(result < 0) {
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
        if(result == -1) {
                PERROR("sigprocmask");
                return;
        }
}

/* Don't call this function directly in a traced program */
static void ust_after_fork_common(ust_fork_info_t *fork_info)
{
	int result;

        /* Restore signals */
        result = sigprocmask(SIG_SETMASK, &fork_info->orig_sigs, NULL);
        if(result == -1) {
                PERROR("sigprocmask");
                return;
        }
}

void ust_after_fork_parent(ust_fork_info_t *fork_info)
{
	/* Reenable signals */
	ust_after_fork_common(fork_info);
}

void ust_after_fork_child(ust_fork_info_t *fork_info)
{
	/* First sanitize the child */
	ust_fork();

	/* Then reenable interrupts */
	ust_after_fork_common(fork_info);
}

