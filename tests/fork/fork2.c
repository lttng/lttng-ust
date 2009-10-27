#include <stdio.h>
#include <unistd.h>

#include <ust/marker.h>

int main()
{
	printf("IN FORK2\n");

	trace_mark(ust, after_exec, MARK_NOARGS);

	return 0;
}

MARKER_LIB;
