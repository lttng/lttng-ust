#include <stdio.h>
#include <unistd.h>

#include "marker.h"


int main()
{
	int result;

	printf("Fork test program\n");
	trace_mark(ust, before_fork, MARK_NOARGS);

	sleep(5);

	result = fork();
	if(result == -1) {
		perror("fork");
		return 1;
	}
	if(result == 0) {
		trace_mark(ust, after_fork_child, MARK_NOARGS);
	}
	else {
		trace_mark(ust, after_fork_parent, MARK_NOARGS);
	}

	return 0;
}

MARKER_LIB;
