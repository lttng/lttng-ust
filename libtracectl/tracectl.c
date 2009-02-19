#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sched.h>

#include "marker.h"

#define UNIX_PATH_MAX 108

//#define SOCKETDIR "/var/run/ust/socks"
#define SOCKETDIR "/tmp/socks"
#define SOCKETDIRLEN sizeof(SOCKETDIR)
#define USTSIGNAL SIGIO

#define DBG(fmt, args...) fprintf(stderr, fmt "\n", ## args)
#define WARN(fmt, args...) fprintf(stderr, "usertrace: WARNING: " fmt "\n", ## args)
#define ERR(fmt, args...) fprintf(stderr, "usertrace: ERROR: " fmt "\n", ## args)
#define PERROR(call) perror("usertrace: ERROR: " call)

#define MAX_MSG_SIZE (100)
#define MSG_NOTIF 1
#define MSG_REGISTER_NOTIF 2

struct tracecmd { /* no padding */
	uint32_t size;
	uint16_t command;
};

//struct listener_arg {
//	int pipe_fd;
//};

struct trctl_msg {
	/* size: the size of all the fields except size itself */
	uint32_t size;
	uint16_t type;
	/* Only the necessary part of the payload is transferred. It
         * may even be none of it.
         */
	char payload[94];
};

pid_t mypid;
char mysocketfile[UNIX_PATH_MAX] = "";
int pfd = -1;


static void print_markers(void)
{
	struct marker_iter iter;

	marker_iter_reset(&iter);
	marker_iter_start(&iter);

	while(iter.marker) {
		fprintf(stderr, "marker: %s_%s \"%s\"\n", iter.marker->channel, iter.marker->name, iter.marker->format);
		marker_iter_next(&iter);
	}
}

void do_command(struct tracecmd *cmd)
{
}

void receive_commands()
{
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

char recvbuf[10000];

int listener_main(void *p)
{
	int result;

	for(;;) {
		uint32_t size;
		struct sockaddr_un addr;
		socklen_t addrlen = sizeof(addr);
		char trace_name[] = "auto";
		char trace_type[] = "ustrelay";

		for(;;) {
			struct trctl_msg msg;
			int len;

			result = len = recvfrom(pfd, recvbuf, sizeof(recvbuf), 0, &addr, &addrlen);
			if(result == -1) {
				PERROR("recvfrom");
				continue;
			}

			if(recvbuf[len-1] == '\n')
				recvbuf[len-1] = '\0';

			fprintf(stderr, "received a message! it's: %s\n", recvbuf);


			if(!strcmp(recvbuf, "print_markers")) {
				print_markers();
			}
			else if(!strcmp(recvbuf, "trace_setup")) {
				DBG("trace setup");

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
			}
			else if(!strcmp(recvbuf, "trace_alloc")) {
				DBG("trace alloc");

				result = ltt_trace_alloc(trace_name);
				if(result < 0) {
					ERR("ltt_trace_alloc failed");
					return;
				}
			}
			else if(!strcmp(recvbuf, "trace_start")) {
				DBG("trace start");

				result = ltt_trace_start(trace_name);
				if(result < 0) {
					ERR("ltt_trace_start failed");
					return;
				}
			}
			else if(!strcmp(recvbuf, "trace_stop")) {
				DBG("trace stop");

				result = ltt_trace_stop(trace_name);
				if(result < 0) {
					ERR("ltt_trace_stop failed");
					return;
				}
			}
			else if(!strcmp(recvbuf, "trace_destroy")) {

				DBG("trace destroy");

				result = ltt_trace_destroy(trace_name);
				if(result < 0) {
					ERR("ltt_trace_destroy failed");
					return;
				}
			}
		}
		next_conn:;
	}
}

void create_listener(void)
{
	int result;
	static char listener_stack[16384];

	result = clone(listener_main, listener_stack+sizeof(listener_stack)-1, CLONE_FS | CLONE_FILES | CLONE_VM | CLONE_SIGHAND | CLONE_THREAD, NULL);
	if(result == -1) {
		perror("clone");
	}
}

/* The signal handler itself. */

void sighandler(int sig)
{
	DBG("sighandler");
	create_listener();
}

/* Called by the app signal handler to chain it to us. */

void chain_signal(void)
{
	sighandler(USTSIGNAL);
}

static int init_socket(void)
{
	int result;
	int fd;
	char pidstr[6];
	int pidlen;

	struct sockaddr_un addr;
	
	result = fd = socket(PF_UNIX, SOCK_DGRAM, 0);
	if(result == -1) {
		PERROR("socket");
		return -1;
	}

	addr.sun_family = AF_UNIX;

	result = snprintf(addr.sun_path, UNIX_PATH_MAX, "%s/%d", SOCKETDIR, mypid);
	if(result >= UNIX_PATH_MAX) {
		ERR("string overflow allocating socket name");
		goto close_sock;
	}
	//DBG("opening socket at %s", addr.sun_path);

	result = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if(result == -1) {
		PERROR("bind");
		goto close_sock;
	}

	strcpy(mysocketfile, addr.sun_path);

	pfd = fd;
	return 0;

	close_sock:
	close(fd);

	return -1;
}

static void destroy_socket(void)
{
	int result;

	if(mysocketfile[0] == '\0')
		return;

	result = unlink(mysocketfile);
	if(result == -1) {
		PERROR("unlink");
	}
}

static int init_signal_handler(void)
{
	/* Attempt to handler SIGIO. If the main program wants to
	 * handle it, fine, it'll override us. They it'll have to
	 * use the chaining function.
	 */

	int result;
	struct sigaction act;

	result = sigemptyset(&act.sa_mask);
	if(result == -1) {
		PERROR("sigemptyset");
		return -1;
	}

	act.sa_handler = sighandler;
	act.sa_flags = SA_RESTART;

	/* Only defer ourselves. Also, try to restart interrupted
	 * syscalls to disturb the traced program as little as possible.
	 */
	result = sigaction(SIGIO, &act, NULL);
	if(result == -1) {
		PERROR("sigaction");
		return -1;
	}

	return 0;
}

static void auto_probe_connect(struct marker *m)
{
	int result;

	result = ltt_marker_connect(m->channel, m->name, "default");
	if(result)
		ERR("ltt_marker_connect");

	DBG("just auto connected marker %s %s to probe default", m->channel, m->name);
}

static void __attribute__((constructor(101))) init0()
{
	DBG("UST_AUTOPROBE constructor");
	if(getenv("UST_AUTOPROBE")) {
		marker_set_new_marker_cb(auto_probe_connect);
	}
}

static void __attribute__((constructor(1000))) init()
{
	int result;

	DBG("UST_TRACE constructor");

	mypid = getpid();

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
	}

	/* Must create socket before signal handler to prevent races
         * on pfd variable.
         */
	result = init_socket();
	if(result == -1) {
		ERR("init_socket error");
		return;
	}
	result = init_signal_handler();
	if(result == -1) {
		ERR("init_signal_handler error");
		return;
	}

	return;

	/* should decrementally destroy stuff if error */

}

/* This is only called if we terminate normally, not with an unhandled signal,
 * so we cannot rely on it. */

static void __attribute__((destructor)) fini()
{
	destroy_socket();
}
