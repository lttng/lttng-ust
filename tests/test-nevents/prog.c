#include <string.h>
#include <stdlib.h>
#include <ust/ust.h>

#define N_ITER 100000

int main()
{
	int i;

	for(i=0; i<N_ITER; i++) {
		trace_mark(ust, an_event, "%d", i);
		trace_mark(ust, another_event, "%s", "Hello, World!");
	}

	return 0;
}
