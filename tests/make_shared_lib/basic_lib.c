#include <stdio.h>
#include <ust/marker.h>

void myfunc(void)
{
	ust_marker(in_lib, MARK_NOARGS);
	printf("testfunc\n");
}

//MARKER_LIB
