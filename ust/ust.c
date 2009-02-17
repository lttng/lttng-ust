#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

#define UNIX_PATH_MAX 108
#define SOCK_DIR "/tmp/socks"
#define UST_SIGNAL SIGIO

struct ust_msg {
	char *raw;
};

void parse_opts(int argc, char **argv)
{
	int flags, opt;
	int nsecs, tfnd;

	nsecs = 0;
	tfnd = 0;
	flags = 0;
	while ((opt = getopt(argc, argv, "nt:")) != -1) {
		switch (opt) {
		case 'n':
			flags = 1;
			break;
		case 't':
			nsecs = atoi(optarg);
			tfnd = 1;
			break;
		default:	/* '?' */
			fprintf(stderr, "Usage: %s [-t nsecs] [-n] name\n",
				argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	printf("flags=%d; tfnd=%d; optind=%d\n", flags, tfnd, optind);

	if (optind >= argc) {
		fprintf(stderr, "Expected argument after options\n");
		exit(EXIT_FAILURE);
	}

	printf("name argument = %s\n", argv[optind]);

	/* Other code omitted */

	exit(EXIT_SUCCESS);

}

void signal_process(pid_t pid)
{
	int result;

	result = kill(pid, UST_SIGNAL);
	if(result == -1) {
		perror("kill");
		return;
	}

	sleep(1);
}

int send_message(pid_t pid, const char *msg)
{
	int fd;
	int result;
	struct sockaddr_un addr;

	result = fd = socket(PF_UNIX, SOCK_DGRAM, 0);
	if(result == -1) {
		perror("socket");
		return 1;
	}

	addr.sun_family = AF_UNIX;

	result = snprintf(addr.sun_path, UNIX_PATH_MAX, "%s/%d", SOCK_DIR, pid);
	if(result >= UNIX_PATH_MAX) {
		fprintf(stderr, "string overflow allocating socket name");
		return 1;
	}

	char buf[] = "print_markers\n";

	signal_process(pid);

	result = sendto(fd, buf, sizeof(buf), 0, (struct sockaddr *)&addr, sizeof(addr));
	if(result == -1) {
		perror("sendto");
		return 1;
	}

//	result = fd = open(sockfile, O_RDWR);
//	if(result == -1 && errno == ENXIO) {
//		fprintf(stderr, "signalling process\n");
//
//		result = fd = open(sockfile, O_RDWR);
//		if(result == -1) {
//			perror("open");
//			return 1;
//		}
//	}
//	else if(result == -1) {
//		perror("open");
//		return 1;
//	}

}

int main(int argc, char *argv[])
{
	pid_t pid = atoi(argv[1]);

	char *msg = argv[2];

	send_message(pid, msg);

	return 0;
}
