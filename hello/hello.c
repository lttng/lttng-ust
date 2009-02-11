#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

#include "../libmarkers/marker.h"
#include "usterr.h"
#include "tracer.h"
#include "marker-control.h"

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

//sig_atomic_t must_quit;

void inthandler(int sig)
{
	printf("in handler\n");
	exit(0);
}

int init_int_handler(void)
{
	int result;
	struct sigaction act;

	result = sigemptyset(&act.sa_mask);
	if(result == -1) {
		PERROR("sigemptyset");
		return -1;
	}

	act.sa_handler = inthandler;
	act.sa_flags = SA_RESTART;

	/* Only defer ourselves. Also, try to restart interrupted
	 * syscalls to disturb the traced program as little as possible.
	 */
	result = sigaction(SIGINT, &act, NULL);
	if(result == -1) {
		PERROR("sigaction");
		return -1;
	}

	return 0;
}

//ust// DEFINE_MUTEX(probes_mutex);
//ust// 
//ust// static LIST_HEAD(probes_registered_list);
//ust// 
//ust// int ltt_marker_connect(const char *channel, const char *mname,
//ust// 		       const char *pname)
//ust// 
//ust// {
//ust// 	int ret;
//ust// 	struct ltt_active_marker *pdata;
//ust// 	struct ltt_available_probe *probe;
//ust// 
//ust// 	ltt_lock_traces();
//ust// 	mutex_lock(&probes_mutex);
//ust// 	probe = get_probe_from_name(pname);
//ust// 	if (!probe) {
//ust// 		ret = -ENOENT;
//ust// 		goto end;
//ust// 	}
//ust// 	pdata = marker_get_private_data(channel, mname, probe->probe_func, 0);
//ust// 	if (pdata && !IS_ERR(pdata)) {
//ust// 		ret = -EEXIST;
//ust// 		goto end;
//ust// 	}
//ust// 	pdata = kmem_cache_zalloc(markers_loaded_cachep, GFP_KERNEL);
//ust// 	if (!pdata) {
//ust// 		ret = -ENOMEM;
//ust// 		goto end;
//ust// 	}
//ust// 	pdata->probe = probe;
//ust// 	/*
//ust// 	 * ID has priority over channel in case of conflict.
//ust// 	 */
//ust// 	ret = marker_probe_register(channel, mname, NULL,
//ust// 		probe->probe_func, pdata);
//ust// 	if (ret)
//ust// 		kmem_cache_free(markers_loaded_cachep, pdata);
//ust// 	else
//ust// 		list_add(&pdata->node, &markers_loaded_list);
//ust// end:
//ust// 	mutex_unlock(&probes_mutex);
//ust// 	ltt_unlock_traces();
//ust// 	return ret;
//ust// }
//ust// 
//ust// 
//ust// int ltt_probe_register(struct ltt_available_probe *pdata)
//ust// {
//ust// 	int ret = 0;
//ust// 	int comparison;
//ust// 	struct ltt_available_probe *iter;
//ust// 
//ust// 	mutex_lock(&probes_mutex);
//ust// 	list_for_each_entry_reverse(iter, &probes_registered_list, node) {
//ust// 		comparison = strcmp(pdata->name, iter->name);
//ust// 		if (!comparison) {
//ust// 			ret = -EBUSY;
//ust// 			goto end;
//ust// 		} else if (comparison > 0) {
//ust// 			/* We belong to the location right after iter. */
//ust// 			list_add(&pdata->node, &iter->node);
//ust// 			goto end;
//ust// 		}
//ust// 	}
//ust// 	/* Should be added at the head of the list */
//ust// 	list_add(&pdata->node, &probes_registered_list);
//ust// end:
//ust// 	mutex_unlock(&probes_mutex);
//ust// 	return ret;
//ust// }
//ust// 
//ust// 
//ust// struct ltt_available_probe default_probe = {
//ust// 	.name = "default",
//ust// 	.format = NULL,
//ust// 	.probe_func = ltt_vtrace,
//ust// 	.callbacks[0] = ltt_serialize_data,
//ust// };

int main()
{
	int result;

	init_int_handler();

	init_ustrelay_transport();

	printf("page size is %d\n", sysconf(_SC_PAGE_SIZE));

	char trace_name[] = "theusttrace";
	char trace_type[] = "ustrelay";

	marker_control_init();

	marker_probe_register("abc", "testmark", "", probe, NULL);
	marker_probe_register("metadata", "core_marker_id", "channel %s name %s event_id %hu int #1u%zu long #1u%zu pointer #1u%zu size_t #1u%zu alignment #1u%u", probe, NULL);
//ust//	result = ltt_probe_register(&default_probe);
//ust//	if(result)
//ust//		ERR("ltt_probe_register");
	
	result = ltt_marker_connect("abc", "testmark2", "default");
	if(result)
		ERR("ltt_marker_connect");


	result = ltt_trace_setup(trace_name);
	if(result < 0) {
		ERR("ltt_trace_setup failed");
		return 1;
	}

	result = ltt_trace_set_type(trace_name, trace_type);
	if(result < 0) {
		ERR("ltt_trace_set_type failed");
		return 1;
	}

	result = ltt_trace_alloc(trace_name);
	if(result < 0) {
		ERR("ltt_trace_alloc failed");
		return 1;
	}

	result = ltt_trace_start(trace_name);
	if(result < 0) {
		ERR("ltt_trace_start failed");
		return 1;
	}


	printf("Hello, World!\n");

	for(;;) {
		trace_mark(abc, testmark, "", MARK_NOARGS);
		trace_mark(abc, testmark2, "", MARK_NOARGS);
		sleep(1);
	}

	scanf("%*s");

	return 0;
}
