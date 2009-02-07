#include <stdio.h>
#include <unistd.h>

#include "../libmarkers/marker.h"

void probe(const struct marker *mdata,
		void *probe_private, void *call_private,
		const char *fmt, va_list *args)
{
	printf("In probe\n");
}

int main()
{
	printf("Hello, World!\n");

	marker_probe_register("abc", "testmark", "", probe, NULL);

	trace_mark(abc, testmark, "", MARK_NOARGS);

	scanf("%*s");

	return 0;
}
