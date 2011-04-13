#include <ust/marker.h>

extern myfunc(void);

int main(void)
{
	myfunc();
	ust_marker(in_prog, MARK_NOARGS);
	return 0;
}
