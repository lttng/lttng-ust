#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "../libmarkers/marker.h"
#include "usterr.h"
#include "tracer.h"
#include "marker-control.h"
#include "relay.h"


char consumer_stack[10000];
char trace_name[] = "theusttrace";
char trace_type[] = "ustrelay";

#define CPRINTF(fmt, args...) safe_printf(fmt "\n", ## args)

int safe_printf(const char *fmt, ...)
{
	static char buf[500];
	va_list ap;
	int n;

	va_start(ap, fmt);

	n = vsnprintf(buf, sizeof(buf), fmt, ap);

	write(STDOUT_FILENO, buf, n);

	va_end(ap);
}

int consumer(void *arg)
{
	int result;

	int fd;

	char str[] = "Hello, this is the consumer.\n";

	struct ltt_trace_struct *trace;

	ltt_lock_traces();
	trace = _ltt_trace_find(trace_name);
	ltt_unlock_traces();

	if(trace == NULL) {
		CPRINTF("cannot find trace!");
		return 1;
	}

	CPRINTF("consumer: got a trace: %s with %d channels\n", trace_name, trace->nr_channels);

	struct ltt_channel_struct *chan = &trace->channels[0];

	CPRINTF("channel 1 (%s) active=%u", chan->channel_name, chan->active & 1);

	struct rchan *rchan = chan->trans_channel_data;
	struct rchan_buf *rbuf = rchan->buf;
	struct ltt_channel_buf_struct *lttbuf = chan->buf;
	long consumed_old;

	result = fd = open("trace.out", O_WRONLY | O_CREAT | O_TRUNC, 00644);
	if(result == -1) {
		perror("open");
		return -1;
	}

	for(;;) {
		write(STDOUT_FILENO, str, sizeof(str));

		result = ltt_do_get_subbuf(rbuf, lttbuf, &consumed_old);
		if(result < 0) {
			CPRINTF("ltt_do_get_subbuf: error: %s", strerror(-result));
		}
		else {
			CPRINTF("success!");

			result = write(fd, rbuf->buf_data + (consumed_old & (2 * 4096-1)), 4096);
			ltt_do_put_subbuf(rbuf, lttbuf, consumed_old);
		}

		//CPRINTF("There seems to be %ld bytes available", SUBBUF_TRUNC(local_read(&lttbuf->offset), rbuf->chan) - consumed_old);
		CPRINTF("Commit count %ld", local_read(&lttbuf->commit_count[0]));


		sleep(1);
	}
}

void start_consumer(void)
{
	int result;

	result = clone(consumer, consumer_stack+sizeof(consumer_stack)-1, CLONE_FS | CLONE_FILES | CLONE_VM, NULL);
	if(result == -1) {
		perror("clone");
	}
}

void probe(const struct marker *mdata,
		void *probe_private, void *call_private,
		const char *fmt, va_list *args)
{
	printf("In probe\n");
}

void inthandler(int sig)
{
	printf("in handler\n");
	exit(0);
}

int init_int_handler(void)
{
	int result;
	struct sigaction act;

	result = sigemptyset(&act.sa_mask);
	if(result == -1) {
		PERROR("sigemptyset");
		return -1;
	}

	act.sa_handler = inthandler;
	act.sa_flags = SA_RESTART;

	/* Only defer ourselves. Also, try to restart interrupted
	 * syscalls to disturb the traced program as little as possible.
	 */
	result = sigaction(SIGINT, &act, NULL);
	if(result == -1) {
		PERROR("sigaction");
		return -1;
	}

	return 0;
}

int main()
{
	int result;

	init_int_handler();

	init_ustrelay_transport();

	printf("page size is %d\n", sysconf(_SC_PAGE_SIZE));

	marker_control_init();

	//marker_probe_register("abc", "testmark", "", probe, NULL);
//ust//	marker_probe_register("metadata", "core_marker_id", "channel %s name %s event_id %hu int #1u%zu long #1u%zu pointer #1u%zu size_t #1u%zu alignment #1u%u", probe, NULL);
//ust//	result = ltt_probe_register(&default_probe);
//ust//	if(result)
//ust//		ERR("ltt_probe_register");
	
	//result = ltt_marker_connect("metadata", "testev", "default");
	//if(result)
	//	ERR("ltt_marker_connect");


	result = ltt_trace_setup(trace_name);
	if(result < 0) {
		ERR("ltt_trace_setup failed");
		return 1;
	}

	result = ltt_trace_set_type(trace_name, trace_type);
	if(result < 0) {
		ERR("ltt_trace_set_type failed");
		return 1;
	}

	result = ltt_trace_alloc(trace_name);
	if(result < 0) {
		ERR("ltt_trace_alloc failed");
		return 1;
	}

	result = ltt_trace_start(trace_name);
	if(result < 0) {
		ERR("ltt_trace_start failed");
		return 1;
	}

	start_consumer();
	printf("Hello, World!\n");

	sleep(1);
	for(;;) {
		//trace_mark(abc, testmark, "", MARK_NOARGS);
		//trace_mark(metadata, testev, "", MARK_NOARGS);
		trace_mark(metadata, core_marker_id,
			   "channel %s name %s event_id %hu "
			   "int #1u%zu long #1u%zu pointer #1u%zu "
			   "size_t #1u%zu alignment #1u%u",
			   "abc", "def", (unsigned short)1000,
			   sizeof(int), sizeof(long), sizeof(void *),
			   sizeof(size_t), ltt_get_alignment());
		usleep(100000);
	}

	scanf("%*s");

	return 0;
}
