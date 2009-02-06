#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#define UNIX_PATH_MAX 108

//#define SOCKETDIR "/var/run/ust/socks"
#define SOCKETDIR "/tmp/socks"
#define SOCKETDIRLEN sizeof(SOCKETDIR)
#define USTSIGNAL SIGIO

#define DBG(fmt, args...) fprintf(stderr, fmt "\n", ## args)
#define WARN(fmt, args...) fprintf(stderr, "usertrace: WARNING: " fmt "\n", ## args)
#define ERR(fmt, args...) fprintf(stderr, "usertrace: ERROR: " fmt "\n", ## args)
#define PERROR(call) perror("usertrace: ERROR: " call)

struct tracecmd { /* no padding */
	uint32_t size;
	uint16_t command;
};


pid_t mypid;
char mysocketfile[UNIX_PATH_MAX] = "";

void do_command(struct tracecmd *cmd)
{
}

void receive_commands()
{
}

/* The signal handler itself. */

void sighandler(int sig)
{
	DBG("sighandler");
	receive_commands();
}

/* Called by the app signal handler to chain it to us. */

void chain_signal()
{
	sighandler(USTSIGNAL);
}

int init_socket()
{
	int result;
	int fd;
	char pidstr[6];
	int pidlen;

	struct sockaddr_un addr;
	
	result = fd = socket(PF_UNIX, SOCK_SEQPACKET, 0);
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

	close_sock:
	close(fd);

	return -1;
}

void destroy_socket()
{
	int result;

	if(mysocketfile[0] == '\0')
		return;

	result = unlink(mysocketfile);
	if(result == -1) {
		PERROR("unlink");
	}
}

int init_signal_handler(void)
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

void __attribute__((constructor)) init()
{
	int result;

	mypid = getpid();

	/* if using instead seperate thread, then should create thread */
	result = init_signal_handler();
	result = init_socket();

	return;

	/* should decrementally destroy stuff if error */

}

/* This is only called if we terminate normally, not with an unhandled signal,
 * so we cannot rely on it. */

void __attribute__((destructor)) fini()
{
	destroy_socket();
}
