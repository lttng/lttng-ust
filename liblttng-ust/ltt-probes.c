/*
 * ltt-probes.c
 *
 * Copyright 2010 (c) - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Holds LTTng probes registry.
 *
 * Dual LGPL v2.1/GPL v2 license.
 */

#include <string.h>
#include <errno.h>
#include <urcu/list.h>
#include <lttng/core.h>
#include <lttng/ust-events.h>
#include <assert.h>

#include "ltt-tracer-core.h"

/*
 * probe list is protected by ust_lock()/ust_unlock().
 */
static CDS_LIST_HEAD(probe_list);

static
const struct lttng_event_desc *find_event(const char *name)
{
	struct lttng_probe_desc *probe_desc;
	int i;

	cds_list_for_each_entry(probe_desc, &probe_list, head) {
		for (i = 0; i < probe_desc->nr_events; i++) {
			if (!strcmp(probe_desc->event_desc[i].name, name))
				return &probe_desc->event_desc[i];
		}
	}
	return NULL;
}

int ltt_probe_register(struct lttng_probe_desc *desc)
{
	int ret = 0;
	int i;

	ust_lock();
	/*
	 * TODO: This is O(N^2). Turn into a hash table when probe registration
	 * overhead becomes an issue.
	 */
	for (i = 0; i < desc->nr_events; i++) {
		if (find_event(desc->event_desc[i].name)) {
			ret = -EEXIST;
			goto end;
		}
	}
	cds_list_add(&desc->head, &probe_list);

	/*
	 * fix the events awaiting probe load.
	 */
	for (i = 0; i < desc->nr_events; i++) {
		ret = pending_probe_fix_events(&desc->event_desc[i]);
		assert(!ret);
	}
end:
	ust_unlock();
	return ret;
}

void ltt_probe_unregister(struct lttng_probe_desc *desc)
{
	ust_lock();
	cds_list_del(&desc->head);
	ust_unlock();
}

/*
 * called with UST lock held.
 */
const struct lttng_event_desc *ltt_event_get(const char *name)
{
	const struct lttng_event_desc *event;

	event = find_event(name);
	if (!event)
		return NULL;
	return event;
}

void ltt_event_put(const struct lttng_event_desc *event)
{
}

#if 0
static
void *tp_list_start(struct seq_file *m, loff_t *pos)
{
	struct lttng_probe_desc *probe_desc;
	int iter = 0, i;

	pthread_mutex_lock(&probe_mutex);
	cds_list_for_each_entry(probe_desc, &probe_list, head) {
		for (i = 0; i < probe_desc->nr_events; i++) {
			if (iter++ >= *pos)
				return (void *) &probe_desc->event_desc[i];
		}
	}
	/* End of list */
	return NULL;
}

static
void *tp_list_next(struct seq_file *m, void *p, loff_t *ppos)
{
	struct lttng_probe_desc *probe_desc;
	int iter = 0, i;

	(*ppos)++;
	cds_list_for_each_entry(probe_desc, &probe_list, head) {
		for (i = 0; i < probe_desc->nr_events; i++) {
			if (iter++ >= *ppos)
				return (void *) &probe_desc->event_desc[i];
		}
	}
	/* End of list */
	return NULL;
}

static
void tp_list_stop(struct seq_file *m, void *p)
{
	pthread_mutex_unlock(&probe_mutex);
}

static
int tp_list_show(struct seq_file *m, void *p)
{
	const struct lttng_event_desc *probe_desc = p;

	/*
	 * Don't export lttng internal events (metadata).
	 */
	if (!strncmp(probe_desc->name, "lttng_", sizeof("lttng_") - 1))
		return 0;
	seq_printf(m,	"event { name = %s; };\n",
		   probe_desc->name);
	return 0;
}

static
const struct seq_operations lttng_tracepoint_list_seq_ops = {
	.start = tp_list_start,
	.next = tp_list_next,
	.stop = tp_list_stop,
	.show = tp_list_show,
};

static
int lttng_tracepoint_list_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &lttng_tracepoint_list_seq_ops);
}

const struct file_operations lttng_tracepoint_list_fops = {
	.open = lttng_tracepoint_list_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};
#endif //0
