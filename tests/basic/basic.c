#include <stdio.h>
#include <unistd.h>

#include "marker.h"


int main()
{
	int i;

	printf("Basic test program\n");

	for(i=0; i<50; i++) {
		trace_mark(ust, bar, "str %s", "FOOBAZ");
		trace_mark(ust, bar2, "number1 %d number2 %d", 53, 9800);
		usleep(100000);
	}

	return 0;
}

MARKER_LIB;
