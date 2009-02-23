#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <stdio.h>
#include <stdlib.h>

#define UNIX_PATH_MAX 108
#define SOCK_DIR "/tmp/socks"
#define UST_SIGNAL SIGIO

static void signal_process(pid_t pid)
{
	int result;

	result = kill(pid, UST_SIGNAL);
	if(result == -1) {
		perror("kill");
		return;
	}

	sleep(1);
}

int send_message(pid_t pid, const char *msg, const char *reply)
{
	int fd;
	int result;
	struct sockaddr_un addr;
	char *buf;

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

	asprintf(&buf, "%s\n", msg);

	signal_process(pid);

	result = sendto(fd, buf, strlen(buf), 0, (struct sockaddr *)&addr, sizeof(addr));
	if(result == -1) {
		perror("sendto");
		return 1;
	}

	free(buf);

	return 0;
}


