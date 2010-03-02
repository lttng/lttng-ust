#include <string.h>
#include <stdlib.h>
#include <ust/ust.h>

#define N_ITER 100000

int main()
{
	int i;
	const char teststr[] = "Hello World! 1234567890abc";
	void *ptrs[N_ITER];

	for(i=0; i<N_ITER; i++) {
		trace_mark(ust, an_event, "%d", i);
		trace_mark(ust, another_event, "%s", "Hello, World!");
	}

//	ltt_trace_stop("auto");
//	ltt_trace_destroy("auto");
//	sleep(2);

	return 0;
}
