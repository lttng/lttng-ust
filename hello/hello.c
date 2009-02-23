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
	int i;

	init_int_handler();

	printf("Hello, World!\n");

	sleep(1);
	for(i=0; i<50; i++) {
		trace_mark(ust, bar, "str %s", "FOOBAZ");
		trace_mark(ust, bar2, "number1 %d number2 %d", 53, 9800);
		usleep(100000);
	}

	scanf("%*s");

	return 0;
}

MARKER_LIB
