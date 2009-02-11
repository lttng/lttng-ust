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

DEFINE_MUTEX(probes_mutex);

static LIST_HEAD(probes_registered_list);

int ltt_marker_connect(const char *channel, const char *mname,
		       const char *pname)

{
	int ret;
	struct ltt_active_marker *pdata;
	struct ltt_available_probe *probe;

	ltt_lock_traces();
	mutex_lock(&probes_mutex);
	probe = get_probe_from_name(pname);
	if (!probe) {
		ret = -ENOENT;
		goto end;
	}
	pdata = marker_get_private_data(channel, mname, probe->probe_func, 0);
	if (pdata && !IS_ERR(pdata)) {
		ret = -EEXIST;
		goto end;
	}
	pdata = kmem_cache_zalloc(markers_loaded_cachep, GFP_KERNEL);
	if (!pdata) {
		ret = -ENOMEM;
		goto end;
	}
	pdata->probe = probe;
	/*
	 * ID has priority over channel in case of conflict.
	 */
	ret = marker_probe_register(channel, mname, NULL,
		probe->probe_func, pdata);
	if (ret)
		kmem_cache_free(markers_loaded_cachep, pdata);
	else
		list_add(&pdata->node, &markers_loaded_list);
end:
	mutex_unlock(&probes_mutex);
	ltt_unlock_traces();
	return ret;
}


int ltt_probe_register(struct ltt_available_probe *pdata)
{
	int ret = 0;
	int comparison;
	struct ltt_available_probe *iter;

	mutex_lock(&probes_mutex);
	list_for_each_entry_reverse(iter, &probes_registered_list, node) {
		comparison = strcmp(pdata->name, iter->name);
		if (!comparison) {
			ret = -EBUSY;
			goto end;
		} else if (comparison > 0) {
			/* We belong to the location right after iter. */
			list_add(&pdata->node, &iter->node);
			goto end;
		}
	}
	/* Should be added at the head of the list */
	list_add(&pdata->node, &probes_registered_list);
end:
	mutex_unlock(&probes_mutex);
	return ret;
}


struct ltt_available_probe default_probe = {
	.name = "default",
	.format = NULL,
	.probe_func = ltt_vtrace,
	.callbacks[0] = ltt_serialize_data,
};

int main()
{
	int result;

	init_int_handler();

	init_ustrelay_transport();

	printf("page size is %d\n", sysconf(_SC_PAGE_SIZE));

	char trace_name[] = "theusttrace";
	char trace_type[] = "ustrelay";

	marker_probe_register("abc", "testmark", "", probe, NULL);
	marker_probe_register("metadata", "core_marker_id", "channel %s name %s event_id %hu int #1u%zu long #1u%zu pointer #1u%zu size_t #1u%zu alignment #1u%u", probe, NULL);
	result = ltt_probe_register(&default_probe);
	if(result)
		ERR("ltt_probe_register");
	
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
