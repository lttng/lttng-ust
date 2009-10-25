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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sched.h>
#include <fcntl.h>
#include <poll.h>
#include <regex.h>

#include <urcu-bp.h>

#include <ust/marker.h>
#include "tracer.h"
#include "usterr.h"
#include "ustcomm.h"
#include "relay.h" /* FIXME: remove */
#include "marker-control.h"

//#define USE_CLONE

#define USTSIGNAL SIGIO

#define MAX_MSG_SIZE (100)
#define MSG_NOTIF 1
#define MSG_REGISTER_NOTIF 2

char consumer_stack[10000];

/* This should only be accessed by the constructor, before the creation
 * of the listener, and then only by the listener.
 */
s64 pidunique = -1LL;

struct list_head blocked_consumers = LIST_HEAD_INIT(blocked_consumers);

static struct ustcomm_app ustcomm_app;

struct tracecmd { /* no padding */
	uint32_t size;
	uint16_t command;
};

/* volatile because shared between the listener and the main thread */
volatile sig_atomic_t buffers_to_export = 0;

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

	/* args to ltt_do_get_subbuf */
	struct rchan_buf *rbuf;
	struct ltt_channel_buf_struct *lttbuf;

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
		fprintf(fp, "marker: %s/%s %d \"%s\"\n", iter.marker->channel, iter.marker->name, (int)imv_read(iter.marker->state), iter.marker->format);
		marker_iter_next(&iter);
	}
	unlock_markers();
}

static int init_socket(void);

/* This needs to be called whenever a new thread is created. It notifies
 * liburcu of the new thread.
 */

void ust_register_thread(void)
{
	rcu_register_thread();
}

int fd_notif = -1;
void notif_cb(void)
{
	int result;
	struct trctl_msg msg;

	/* FIXME: fd_notif should probably be protected by a spinlock */

	if(fd_notif == -1)
		return;

	msg.type = MSG_NOTIF;
	msg.size = sizeof(msg.type);

	/* FIXME: don't block here */
	result = write(fd_notif, &msg, msg.size+sizeof(msg.size));
	if(result == -1) {
		PERROR("write");
		return;
	}
}

/* Ask the daemon to collect a trace called trace_name and being
 * produced by this pid.
 *
 * The trace must be at least allocated. (It can also be started.)
 * This is because _ltt_trace_find is used.
 */

static void inform_consumer_daemon(const char *trace_name)
{
	int i;
	struct ltt_trace_struct *trace;
	pid_t pid = getpid();
	int result;

	ltt_lock_traces();

	trace = _ltt_trace_find(trace_name);
	if(trace == NULL) {
		WARN("inform_consumer_daemon: could not find trace \"%s\"; it is probably already destroyed", trace_name);
		goto finish;
	}

	for(i=0; i < trace->nr_channels; i++) {
		result = ustcomm_request_consumer(pid, trace->channels[i].channel_name);
		if(result == -1) {
			WARN("Failed to request collection for channel %s. Is the daemon available?", trace->channels[i].channel_name);
			/* continue even if fail */
		}
		buffers_to_export++;
	}

	finish:
	ltt_unlock_traces();
}

void process_blocked_consumers(void)
{
	int n_fds = 0;
	struct pollfd *fds;
	struct blocked_consumer *bc;
	int idx = 0;
	char inbuf;
	int result;

	list_for_each_entry(bc, &blocked_consumers, list) {
		n_fds++;
	}

	fds = (struct pollfd *) malloc(n_fds * sizeof(struct pollfd));
	if(fds == NULL) {
		ERR("malloc returned NULL");
		return;
	}

	list_for_each_entry(bc, &blocked_consumers, list) {
		fds[idx].fd = bc->fd_producer;
		fds[idx].events = POLLIN;
		bc->tmp_poll_idx = idx;
		idx++;
	}

	while((result = poll(fds, n_fds, 0)) == -1 && errno == EINTR)
		/* nothing */;
	if(result == -1) {
		PERROR("poll");
		return;
	}

	list_for_each_entry(bc, &blocked_consumers, list) {
		if(fds[bc->tmp_poll_idx].revents) {
			long consumed_old = 0;
			char *reply;

			result = read(bc->fd_producer, &inbuf, 1);
			if(result == -1) {
				PERROR("read");
				continue;
			}
			if(result == 0) {
				DBG("PRODUCER END");

				close(bc->fd_producer);

				list_del(&bc->list);

				result = ustcomm_send_reply(&bc->server, "END", &bc->src);
				if(result < 0) {
					ERR("ustcomm_send_reply failed");
					continue;
				}

				continue;
			}

			result = ltt_do_get_subbuf(bc->rbuf, bc->lttbuf, &consumed_old);
			if(result == -EAGAIN) {
				WARN("missed buffer?");
				continue;
			}
			else if(result < 0) {
				DBG("ltt_do_get_subbuf: error: %s", strerror(-result));
			}
			asprintf(&reply, "%s %ld", "OK", consumed_old);
			result = ustcomm_send_reply(&bc->server, reply, &bc->src);
			if(result < 0) {
				ERR("ustcomm_send_reply failed");
				free(reply);
				continue;
			}
			free(reply);

			list_del(&bc->list);
		}
	}

}

void *listener_main(void *p)
{
	int result;

	ust_register_thread();

	DBG("LISTENER");

	for(;;) {
		char trace_name[] = "auto";
		char trace_type[] = "ustrelay";
		char *recvbuf;
		int len;
		struct ustcomm_source src;

		process_blocked_consumers();

		result = ustcomm_app_recv_message(&ustcomm_app, &recvbuf, &src, 5);
		if(result < 0) {
			WARN("error in ustcomm_app_recv_message");
			continue;
		}
		else if(result == 0) {
			/* no message */
			continue;
		}

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

			result = ustcomm_send_reply(&ustcomm_app.server, ptr, &src);

			free(ptr);
		}
		else if(!strcmp(recvbuf, "start")) {
			/* start is an operation that setups the trace, allocates it and starts it */
			result = ltt_trace_setup(trace_name);
			if(result < 0) {
				ERR("ltt_trace_setup failed");
				return (void *)1;
			}

			result = ltt_trace_set_type(trace_name, trace_type);
			if(result < 0) {
				ERR("ltt_trace_set_type failed");
				return (void *)1;
			}

			result = ltt_trace_alloc(trace_name);
			if(result < 0) {
				ERR("ltt_trace_alloc failed");
				return (void *)1;
			}

			inform_consumer_daemon(trace_name);

			result = ltt_trace_start(trace_name);
			if(result < 0) {
				ERR("ltt_trace_start failed");
				continue;
			}
		}
		else if(!strcmp(recvbuf, "trace_setup")) {
			DBG("trace setup");

			result = ltt_trace_setup(trace_name);
			if(result < 0) {
				ERR("ltt_trace_setup failed");
				return (void *)1;
			}

			result = ltt_trace_set_type(trace_name, trace_type);
			if(result < 0) {
				ERR("ltt_trace_set_type failed");
				return (void *)1;
			}
		}
		else if(!strcmp(recvbuf, "trace_alloc")) {
			DBG("trace alloc");

			result = ltt_trace_alloc(trace_name);
			if(result < 0) {
				ERR("ltt_trace_alloc failed");
				return (void *)1;
			}
		}
		else if(!strcmp(recvbuf, "trace_start")) {
			DBG("trace start");

			result = ltt_trace_start(trace_name);
			if(result < 0) {
				ERR("ltt_trace_start failed");
				continue;
			}
		}
		else if(!strcmp(recvbuf, "trace_stop")) {
			DBG("trace stop");

			result = ltt_trace_stop(trace_name);
			if(result < 0) {
				ERR("ltt_trace_stop failed");
				return (void *)1;
			}
		}
		else if(!strcmp(recvbuf, "trace_destroy")) {

			DBG("trace destroy");

			result = ltt_trace_destroy(trace_name);
			if(result < 0) {
				ERR("ltt_trace_destroy failed");
				return (void *)1;
			}
		}
		else if(nth_token_is(recvbuf, "get_shmid", 0) == 1) {
			struct ltt_trace_struct *trace;
			char trace_name[] = "auto";
			int i;
			char *channel_name;

			DBG("get_shmid");

			channel_name = nth_token(recvbuf, 1);
			if(channel_name == NULL) {
				ERR("get_shmid: cannot parse channel");
				goto next_cmd;
			}

			ltt_lock_traces();
			trace = _ltt_trace_find(trace_name);
			ltt_unlock_traces();

			if(trace == NULL) {
				ERR("cannot find trace!");
				return (void *)1;
			}

			for(i=0; i<trace->nr_channels; i++) {
				struct rchan *rchan = trace->channels[i].trans_channel_data;
				struct rchan_buf *rbuf = rchan->buf;
				struct ltt_channel_struct *ltt_channel = (struct ltt_channel_struct *)rchan->private_data;

				if(!strcmp(trace->channels[i].channel_name, channel_name)) {
					char *reply;

					DBG("the shmid for the requested channel is %d", rbuf->shmid);
					DBG("the shmid for its buffer structure is %d", ltt_channel->buf_shmid);
					asprintf(&reply, "%d %d", rbuf->shmid, ltt_channel->buf_shmid);

					result = ustcomm_send_reply(&ustcomm_app.server, reply, &src);
					if(result) {
						ERR("listener: get_shmid: ustcomm_send_reply failed");
						goto next_cmd;
					}

					free(reply);

					break;
				}
			}

			buffers_to_export--;
		}
		else if(nth_token_is(recvbuf, "get_n_subbufs", 0) == 1) {
			struct ltt_trace_struct *trace;
			char trace_name[] = "auto";
			int i;
			char *channel_name;

			DBG("get_n_subbufs");

			channel_name = nth_token(recvbuf, 1);
			if(channel_name == NULL) {
				ERR("get_n_subbufs: cannot parse channel");
				goto next_cmd;
			}

			ltt_lock_traces();
			trace = _ltt_trace_find(trace_name);
			ltt_unlock_traces();

			if(trace == NULL) {
				ERR("cannot find trace!");
				return (void *)1;
			}

			for(i=0; i<trace->nr_channels; i++) {
				struct rchan *rchan = trace->channels[i].trans_channel_data;

				if(!strcmp(trace->channels[i].channel_name, channel_name)) {
					char *reply;

					DBG("the n_subbufs for the requested channel is %zd", rchan->n_subbufs);
					asprintf(&reply, "%zd", rchan->n_subbufs);

					result = ustcomm_send_reply(&ustcomm_app.server, reply, &src);
					if(result) {
						ERR("listener: get_n_subbufs: ustcomm_send_reply failed");
						goto next_cmd;
					}

					free(reply);

					break;
				}
			}
		}
		else if(nth_token_is(recvbuf, "get_subbuf_size", 0) == 1) {
			struct ltt_trace_struct *trace;
			char trace_name[] = "auto";
			int i;
			char *channel_name;

			DBG("get_subbuf_size");

			channel_name = nth_token(recvbuf, 1);
			if(channel_name == NULL) {
				ERR("get_subbuf_size: cannot parse channel");
				goto next_cmd;
			}

			ltt_lock_traces();
			trace = _ltt_trace_find(trace_name);
			ltt_unlock_traces();

			if(trace == NULL) {
				ERR("cannot find trace!");
				return (void *)1;
			}

			for(i=0; i<trace->nr_channels; i++) {
				struct rchan *rchan = trace->channels[i].trans_channel_data;

				if(!strcmp(trace->channels[i].channel_name, channel_name)) {
					char *reply;

					DBG("the subbuf_size for the requested channel is %zd", rchan->subbuf_size);
					asprintf(&reply, "%zd", rchan->subbuf_size);

					result = ustcomm_send_reply(&ustcomm_app.server, reply, &src);
					if(result) {
						ERR("listener: get_subbuf_size: ustcomm_send_reply failed");
						goto next_cmd;
					}

					free(reply);

					break;
				}
			}
		}
		else if(nth_token_is(recvbuf, "load_probe_lib", 0) == 1) {
			char *libfile;

			libfile = nth_token(recvbuf, 1);

			DBG("load_probe_lib loading %s", libfile);
		}
		else if(nth_token_is(recvbuf, "get_subbuffer", 0) == 1) {
			struct ltt_trace_struct *trace;
			char trace_name[] = "auto";
			int i;
			char *channel_name;

			DBG("get_subbuf");

			channel_name = nth_token(recvbuf, 1);
			if(channel_name == NULL) {
				ERR("get_subbuf: cannot parse channel");
				goto next_cmd;
			}

			ltt_lock_traces();
			trace = _ltt_trace_find(trace_name);
			ltt_unlock_traces();

			if(trace == NULL) {
				ERR("cannot find trace!");
				return (void *)1;
			}

			for(i=0; i<trace->nr_channels; i++) {
				struct rchan *rchan = trace->channels[i].trans_channel_data;

				if(!strcmp(trace->channels[i].channel_name, channel_name)) {
					struct rchan_buf *rbuf = rchan->buf;
					struct ltt_channel_buf_struct *lttbuf = trace->channels[i].buf;
					struct blocked_consumer *bc;

					bc = (struct blocked_consumer *) malloc(sizeof(struct blocked_consumer));
					if(bc == NULL) {
						ERR("malloc returned NULL");
						goto next_cmd;
					}
					bc->fd_consumer = src.fd;
					bc->fd_producer = lttbuf->data_ready_fd_read;
					bc->rbuf = rbuf;
					bc->lttbuf = lttbuf;
					bc->src = src;
					bc->server = ustcomm_app.server;

					list_add(&bc->list, &blocked_consumers);

					break;
				}
			}
		}
		else if(nth_token_is(recvbuf, "put_subbuffer", 0) == 1) {
			struct ltt_trace_struct *trace;
			char trace_name[] = "auto";
			int i;
			char *channel_name;
			long consumed_old;
			char *consumed_old_str;
			char *endptr;

			DBG("put_subbuf");

			channel_name = strdup_malloc(nth_token(recvbuf, 1));
			if(channel_name == NULL) {
				ERR("put_subbuf_size: cannot parse channel");
				goto next_cmd;
			}

			consumed_old_str = strdup_malloc(nth_token(recvbuf, 2));
			if(consumed_old_str == NULL) {
				ERR("put_subbuf: cannot parse consumed_old");
				goto next_cmd;
			}
			consumed_old = strtol(consumed_old_str, &endptr, 10);
			if(*endptr != '\0') {
				ERR("put_subbuf: invalid value for consumed_old");
				goto next_cmd;
			}

			ltt_lock_traces();
			trace = _ltt_trace_find(trace_name);
			ltt_unlock_traces();

			if(trace == NULL) {
				ERR("cannot find trace!");
				return (void *)1;
			}

			for(i=0; i<trace->nr_channels; i++) {
				struct rchan *rchan = trace->channels[i].trans_channel_data;

				if(!strcmp(trace->channels[i].channel_name, channel_name)) {
					struct rchan_buf *rbuf = rchan->buf;
					struct ltt_channel_buf_struct *lttbuf = trace->channels[i].buf;
					char *reply;
					long consumed_old=0;

					result = ltt_do_put_subbuf(rbuf, lttbuf, consumed_old);
					if(result < 0) {
						WARN("ltt_do_put_subbuf: error (subbuf=%s)", channel_name);
						asprintf(&reply, "%s", "ERROR");
					}
					else {
						DBG("ltt_do_put_subbuf: success (subbuf=%s)", channel_name);
						asprintf(&reply, "%s", "OK");
					}

					result = ustcomm_send_reply(&ustcomm_app.server, reply, &src);
					if(result) {
						ERR("listener: put_subbuf: ustcomm_send_reply failed");
						goto next_cmd;
					}

					free(reply);

					break;
				}
			}

			free(channel_name);
			free(consumed_old_str);
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
			printf("%s %s\n", channel_name, marker_name);

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
			printf("%s %s\n", channel_name, marker_name);

			result = ltt_marker_disconnect(channel_name, marker_name, "default");
			if(result < 0) {
				WARN("could not disable marker; channel=%s, name=%s", channel_name, marker_name);
			}
		}
		else if(nth_token_is(recvbuf, "get_pidunique", 0) == 1) {
			char *reply;

			asprintf(&reply, "%lld", pidunique);

			result = ustcomm_send_reply(&ustcomm_app.server, reply, &src);
			if(result) {
				ERR("listener: get_pidunique: ustcomm_send_reply failed");
				goto next_cmd;
			}

			free(reply);
		}
//		else if(nth_token_is(recvbuf, "get_notifications", 0) == 1) {
//			struct ltt_trace_struct *trace;
//			char trace_name[] = "auto";
//			int i;
//			char *channel_name;
//
//			DBG("get_notifications");
//
//			channel_name = strdup_malloc(nth_token(recvbuf, 1));
//			if(channel_name == NULL) {
//				ERR("put_subbuf_size: cannot parse channel");
//				goto next_cmd;
//			}
//
//			ltt_lock_traces();
//			trace = _ltt_trace_find(trace_name);
//			ltt_unlock_traces();
//
//			if(trace == NULL) {
//				ERR("cannot find trace!");
//				return (void *)1;
//			}
//
//			for(i=0; i<trace->nr_channels; i++) {
//				struct rchan *rchan = trace->channels[i].trans_channel_data;
//				int fd;
//
//				if(!strcmp(trace->channels[i].channel_name, channel_name)) {
//					struct rchan_buf *rbuf = rchan->buf;
//					struct ltt_channel_buf_struct *lttbuf = trace->channels[i].buf;
//
//					result = fd = ustcomm_app_detach_client(&ustcomm_app, &src);
//					if(result == -1) {
//						ERR("ustcomm_app_detach_client failed");
//						goto next_cmd;
//					}
//
//					lttbuf->wake_consumer_arg = (void *) fd;
//
//					smp_wmb();
//
//					lttbuf->call_wake_consumer = 1;
//
//					break;
//				}
//			}
//
//			free(channel_name);
//		}
		else {
			ERR("unable to parse message: %s", recvbuf);
		}

	next_cmd:
		free(recvbuf);
	}
}

volatile sig_atomic_t have_listener = 0;

void create_listener(void)
{
#ifdef USE_CLONE
	static char listener_stack[16384];
	int result;
#else
	pthread_t thread;
#endif

	if(have_listener) {
		WARN("not creating listener because we already had one");
		return;
	}

#ifdef USE_CLONE
	result = clone((int (*)(void *)) listener_main, listener_stack+sizeof(listener_stack)-1, CLONE_FS | CLONE_FILES | CLONE_VM | CLONE_SIGHAND | CLONE_THREAD, NULL);
	if(result == -1) {
		perror("clone");
		return;
	}
#else

	pthread_create(&thread, NULL, listener_main, NULL);
#endif

	have_listener = 1;
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

	DBG("auto connected marker %s %s to probe default", m->channel, m->name);

}

static void __attribute__((constructor)) init()
{
	int result;
	char* autoprobe_val = NULL;

	/* Assign the pidunique, to be able to differentiate the processes with same
	 * pid, (before and after an exec).
	 */
	pidunique = make_pidunique();

	/* Initialize RCU in case the constructor order is not good. */
	urcu_init();

	/* It is important to do this before events start to be generated. */
	ust_register_thread();

	DBG("Tracectl constructor");

	/* Must create socket before signal handler to prevent races.
         */
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

	if(getenv("UST_TRACE")) {
		char trace_name[] = "auto";
		char trace_type[] = "ustrelay";

		DBG("starting early tracing");

		/* Ensure marker control is initialized */
		init_marker_control();

		/* Ensure relay is initialized */
		init_ustrelay_transport();

		/* Ensure markers are initialized */
		init_markers();

		/* In case. */
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

	result = ltt_trace_destroy("auto");
	if(result == -1) {
		ERR("ltt_trace_destroy error");
	}
}

static int trace_recording(void)
{
	int retval = 0;
	struct ltt_trace_struct *trace;

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
	if(trace_recording() && buffers_to_export) {
		int total = 0;
		DBG("Keeping process alive for consumer daemon...");
		while(buffers_to_export) {
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

	ustcomm_fini_app(&ustcomm_app);
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
 */

void ust_fork(void)
{
	struct blocked_consumer *bc;
	struct blocked_consumer *deletable_bc = NULL;
	int result;

	DBG("ust: forking");
	ltt_trace_stop("auto");
	ltt_trace_destroy("auto");
	/* Delete all active connections */
	ustcomm_close_all_connections(&ustcomm_app.server);

	/* Delete all blocked consumers */
	list_for_each_entry(bc, &blocked_consumers, list) {
		close(bc->fd_producer);
		close(bc->fd_consumer);
		free(deletable_bc);
		deletable_bc = bc;
		list_del(&bc->list);
	}

	have_listener = 0;
	create_listener();
	init_socket();
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

