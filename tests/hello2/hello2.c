#include <stdio.h>
#include <time.h>
#include <errno.h>

#include "marker.h"
int main()
{
	int i;
	struct timespec tv;
	int result;

	tv.tv_sec = 1;
	tv.tv_nsec = 0;

	do {
		result = nanosleep(&tv, &tv);
	} while(result == -1 && errno == EINTR);

	printf("Hello, World!\n");

	for(i=0; i<500; i++) {
		trace_mark(ust, bar, "str %d", i);
		trace_mark(ust, bar2, "number1 %d number2 %d", (int)53, (int)9800);
	}

//	ltt_trace_stop("auto");
//	ltt_trace_destroy("auto");

	return 0;
}
MARKER_LIB;
