#include <stdio.h>
#include <unistd.h>
#include "marker.h"
int main()
{
	int i;

//	sleep(1);

	printf("Hello, World!\n");

	for(i=0; i<500; i++) {
		trace_mark(ust, bar, "str %d", i);
		trace_mark(ust, bar2, "number1 %d number2 %d", (int)53, (int)9800);
		usleep(20);
	}

	return 0;
}
MARKER_LIB;
