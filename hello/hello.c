#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

#include "../libmarkers/marker.h"
#include "usterr.h"
#include "tracer.h"

void probe(const struct marker *mdata,
		void *probe_private, void *call_private,
		const char *fmt, va_list *args)
{
	printf("In probe\n");
}

//ust// void try_map()
//ust// {
//ust// 	char *m;
//ust// 
//ust// 	/* maybe add MAP_LOCKED */
//ust// 	m = mmap(NULL, 4096, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE , -1, 0);
//ust// 	if(m == (char*)-1) {
//ust// 		perror("mmap");
//ust// 		return;
//ust// 	}
//ust// 
//ust// 	printf("The mapping is at %p.\n", m);
//ust// 	strcpy(m, "Hello, Mapping!");
//ust// }

int main()
{
	int result;

	init_ustrelay_transport();

	char trace_name[] = "theusttrace";
	char trace_type[] = "usttrace";

	marker_probe_register("abc", "testmark", "", probe, NULL);
	marker_probe_register("metadata", "core_marker_id", "channel %s name %s event_id %hu int #1u%zu long #1u%zu pointer #1u%zu size_t #1u%zu alignment #1u%u", probe, NULL);

	result = ltt_trace_setup(trace_name);
	if(result < 0) {
		ERR("ltt_trace_setup failed");
		return 1;
	}

//ust//	result = ltt_trace_set_type(trace_name, trace_type);
//ust//	if(result < 0) {
//ust//		ERR("ltt_trace_set_type failed");
//ust//		return 1;
//ust//	}

	result = ltt_trace_alloc(trace_name);
	if(result < 0) {
		ERR("ltt_trace_alloc failed");
		return 1;
	}

//	try_map();

	printf("Hello, World!\n");


	trace_mark(abc, testmark, "", MARK_NOARGS);

	scanf("%*s");

	return 0;
}
