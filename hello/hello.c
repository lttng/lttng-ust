#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

#include "../libmarkers/marker.h"

void probe(const struct marker *mdata,
		void *probe_private, void *call_private,
		const char *fmt, va_list *args)
{
	printf("In probe\n");
}

void try_map()
{
	char *m;

	/* maybe add MAP_LOCKED */
	m = mmap(NULL, 4096, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE , -1, 0);
	if(m == (char*)-1) {
		perror("mmap");
		return;
	}

	printf("The mapping is at %p.\n", m);
	strcpy(m, "Hello, Mapping!");
}

int main()
{
	//ltt_trace_create();

	try_map();

	printf("Hello, World!\n");

	marker_probe_register("abc", "testmark", "", probe, NULL);

	trace_mark(abc, testmark, "", MARK_NOARGS);

	scanf("%*s");

	return 0;
}
