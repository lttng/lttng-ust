#include <stdio.h>
#include <unistd.h>

#include <ust/marker.h>

int main()
{
	printf("Basic test program\n");

	for(;;) {
		trace_mark(ust, bar, "str %s", "FOOBAZ");
		trace_mark(ust, bar2, "number1 %d number2 %d", 53, 9800);
		usleep(1000000);
	}

	return 0;
}

MARKER_LIB;
