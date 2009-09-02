/*
 * Copyright (C) 2007 Mathieu Desnoyers
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 *
 * LTT marker control module over /proc
 */

//ust// #include <linux/proc_fs.h>
//ust// #include <linux/module.h>
//ust// #include <linux/stat.h>
//ust// #include <linux/vmalloc.h>
//ust// #include <linux/marker.h>
//ust// #include <linux/ltt-tracer.h>
//ust// #include <linux/uaccess.h>
//ust// #include <linux/string.h>
//ust// #include <linux/ctype.h>
//ust// #include <linux/list.h>
//ust// #include <linux/mutex.h>
//ust// #include <linux/seq_file.h>
//ust// #include <linux/slab.h>
#include <ctype.h>

#include "kernelcompat.h"
//#include "list.h"
#include "tracer.h"
#include "localerr.h"

#define DEFAULT_CHANNEL "cpu"
#define DEFAULT_PROBE "default"

LIST_HEAD(probes_list);

/*
 * Mutex protecting the probe slab cache.
 * Nests inside the traces mutex.
 */
DEFINE_MUTEX(probes_mutex);

struct ltt_available_probe default_probe = {
	.name = "default",
	.format = NULL,
	.probe_func = ltt_vtrace,
	.callbacks[0] = ltt_serialize_data,
};

//ust//static struct kmem_cache *markers_loaded_cachep;
static LIST_HEAD(markers_loaded_list);
/*
 * List sorted by name strcmp order.
 */
static LIST_HEAD(probes_registered_list);

//ust// static struct proc_dir_entry *pentry;

//ust// static struct file_operations ltt_fops;

static struct ltt_available_probe *get_probe_from_name(const char *pname)
{
	struct ltt_available_probe *iter;
	int comparison, found = 0;

	if (!pname)
		pname = DEFAULT_PROBE;
	list_for_each_entry(iter, &probes_registered_list, node) {
		comparison = strcmp(pname, iter->name);
		if (!comparison)
			found = 1;
		if (comparison <= 0)
			break;
	}
	if (found)
		return iter;
	else
		return NULL;
}

/* (unused)
static char *skip_spaces(char *buf)
{
	while (*buf != '\0' && isspace(*buf))
		buf++;
	return buf;
}

static char *skip_nonspaces(char *buf)
{
	while (*buf != '\0' && !isspace(*buf))
		buf++;
	return buf;
}

static void get_marker_string(char *buf, char **start,
		char **end)
{
	*start = skip_spaces(buf);
	*end = skip_nonspaces(*start);
	**end = '\0';
}
*/

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

/*
 * Called when a probe does not want to be called anymore.
 */
int ltt_probe_unregister(struct ltt_available_probe *pdata)
{
	int ret = 0;
	struct ltt_active_marker *amark, *tmp;

	mutex_lock(&probes_mutex);
	list_for_each_entry_safe(amark, tmp, &markers_loaded_list, node) {
		if (amark->probe == pdata) {
			ret = marker_probe_unregister_private_data(
				pdata->probe_func, amark);
			if (ret)
				goto end;
			list_del(&amark->node);
			free(amark);
		}
	}
	list_del(&pdata->node);
end:
	mutex_unlock(&probes_mutex);
	return ret;
}

/*
 * Connect marker "mname" to probe "pname".
 * Only allow _only_ probe instance to be connected to a marker.
 */
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
	pdata = zmalloc(sizeof(struct ltt_active_marker));
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
		free(pdata);
	else
		list_add(&pdata->node, &markers_loaded_list);
end:
	mutex_unlock(&probes_mutex);
	ltt_unlock_traces();
	return ret;
}

/*
 * Disconnect marker "mname", probe "pname".
 */
int ltt_marker_disconnect(const char *channel, const char *mname,
			  const char *pname)
{
	struct ltt_active_marker *pdata;
	struct ltt_available_probe *probe;
	int ret = 0;

	mutex_lock(&probes_mutex);
	probe = get_probe_from_name(pname);
	if (!probe) {
		ret = -ENOENT;
		goto end;
	}
	pdata = marker_get_private_data(channel, mname, probe->probe_func, 0);
	if (IS_ERR(pdata)) {
		ret = PTR_ERR(pdata);
		goto end;
	} else if (!pdata) {
		/*
		 * Not registered by us.
		 */
		ret = -EPERM;
		goto end;
	}
	ret = marker_probe_unregister(channel, mname, probe->probe_func, pdata);
	if (ret)
		goto end;
	else {
		list_del(&pdata->node);
		free(pdata);
	}
end:
	mutex_unlock(&probes_mutex);
	return ret;
}

/*
 * function handling proc entry write.
 *
 * connect <channel name> <marker name> [<probe name>]]
 * disconnect <channel name> <marker name> [<probe name>]
 */
//ust// static ssize_t ltt_write(struct file *file, const char __user *buffer,
//ust// 			   size_t count, loff_t *offset)
//ust// {
//ust// 	char *kbuf;
//ust// 	char *iter, *marker_action, *arg[4];
//ust// 	ssize_t ret;
//ust// 	int i;
//ust// 
//ust// 	if (!count)
//ust// 		return -EINVAL;
//ust// 
//ust// 	kbuf = vmalloc(count + 1);
//ust// 	kbuf[count] = '\0';		/* Transform into a string */
//ust// 	ret = copy_from_user(kbuf, buffer, count);
//ust// 	if (ret) {
//ust// 		ret = -EINVAL;
//ust// 		goto end;
//ust// 	}
//ust// 	get_marker_string(kbuf, &marker_action, &iter);
//ust// 	if (!marker_action || marker_action == iter) {
//ust// 		ret = -EINVAL;
//ust// 		goto end;
//ust// 	}
//ust// 	for (i = 0; i < 4; i++) {
//ust// 		arg[i] = NULL;
//ust// 		if (iter < kbuf + count) {
//ust// 			iter++;			/* skip the added '\0' */
//ust// 			get_marker_string(iter, &arg[i], &iter);
//ust// 			if (arg[i] == iter)
//ust// 				arg[i] = NULL;
//ust// 		}
//ust// 	}
//ust// 
//ust// 	if (!arg[0] || !arg[1]) {
//ust// 		ret = -EINVAL;
//ust// 		goto end;
//ust// 	}
//ust// 
//ust// 	if (!strcmp(marker_action, "connect")) {
//ust// 		ret = ltt_marker_connect(arg[0], arg[1], arg[2]);
//ust// 		if (ret)
//ust// 			goto end;
//ust// 	} else if (!strcmp(marker_action, "disconnect")) {
//ust// 		ret = ltt_marker_disconnect(arg[0], arg[1], arg[2]);
//ust// 		if (ret)
//ust// 			goto end;
//ust// 	}
//ust// 	ret = count;
//ust// end:
//ust// 	vfree(kbuf);
//ust// 	return ret;
//ust// }
//ust// 
//ust// static void *s_next(struct seq_file *m, void *p, loff_t *pos)
//ust// {
//ust// 	struct marker_iter *iter = m->private;
//ust// 
//ust// 	marker_iter_next(iter);
//ust// 	if (!iter->marker) {
//ust// 		/*
//ust// 		 * Setting the iter module to -1UL will make sure
//ust// 		 * that no module can possibly hold the current marker.
//ust// 		 */
//ust// 		iter->module = (void *)-1UL;
//ust// 		return NULL;
//ust// 	}
//ust// 	return iter->marker;
//ust// }
//ust// 
//ust// static void *s_start(struct seq_file *m, loff_t *pos)
//ust// {
//ust// 	struct marker_iter *iter = m->private;
//ust// 
//ust// 	if (!*pos)
//ust// 		marker_iter_reset(iter);
//ust// 	marker_iter_start(iter);
//ust// 	if (!iter->marker) {
//ust// 		/*
//ust// 		 * Setting the iter module to -1UL will make sure
//ust// 		 * that no module can possibly hold the current marker.
//ust// 		 */
//ust// 		iter->module = (void *)-1UL;
//ust// 		return NULL;
//ust// 	}
//ust// 	return iter->marker;
//ust// }
//ust// 
//ust// static void s_stop(struct seq_file *m, void *p)
//ust// {
//ust// 	marker_iter_stop(m->private);
//ust// }
//ust// 
//ust// static int s_show(struct seq_file *m, void *p)
//ust// {
//ust// 	struct marker_iter *iter = m->private;
//ust// 
//ust// 	seq_printf(m, "channel: %s marker: %s format: \"%s\" state: %d "
//ust// 		"event_id: %hu call: 0x%p probe %s : 0x%p\n",
//ust// 		iter->marker->channel,
//ust// 		iter->marker->name, iter->marker->format,
//ust// 		_imv_read(iter->marker->state),
//ust// 		iter->marker->event_id,
//ust// 		iter->marker->call,
//ust// 		iter->marker->ptype ? "multi" : "single",
//ust// 		iter->marker->ptype ?
//ust// 		(void*)iter->marker->multi : (void*)iter->marker->single.func);
//ust// 	return 0;
//ust// }
//ust// 
//ust// static const struct seq_operations ltt_seq_op = {
//ust// 	.start = s_start,
//ust// 	.next = s_next,
//ust// 	.stop = s_stop,
//ust// 	.show = s_show,
//ust// };
//ust// 
//ust// static int ltt_open(struct inode *inode, struct file *file)
//ust// {
//ust// 	/*
//ust// 	 * Iterator kept in m->private.
//ust// 	 * Restart iteration on all modules between reads because we do not lock
//ust// 	 * the module mutex between those.
//ust// 	 */
//ust// 	int ret;
//ust// 	struct marker_iter *iter;
//ust// 
//ust// 	iter = kzalloc(sizeof(*iter), GFP_KERNEL);
//ust// 	if (!iter)
//ust// 		return -ENOMEM;
//ust// 
//ust// 	ret = seq_open(file, &ltt_seq_op);
//ust// 	if (ret == 0)
//ust// 		((struct seq_file *)file->private_data)->private = iter;
//ust// 	else
//ust// 		kfree(iter);
//ust// 	return ret;
//ust// }
//ust// 
//ust// static struct file_operations ltt_fops = {
//ust// 	.write = ltt_write,
//ust// 	.open = ltt_open,
//ust// 	.read = seq_read,
//ust// 	.llseek = seq_lseek,
//ust// 	.release = seq_release_private,
//ust// };

static void disconnect_all_markers(void)
{
	struct ltt_active_marker *pdata, *tmp;

	list_for_each_entry_safe(pdata, tmp, &markers_loaded_list, node) {
		marker_probe_unregister_private_data(pdata->probe->probe_func,
			pdata);
		list_del(&pdata->node);
		free(pdata);
	}
}

static char initialized = 0;

void __attribute__((constructor)) init_marker_control(void)
{
	if(!initialized) {
		int ret;

//ust//	pentry = create_proc_entry("ltt", S_IRUSR|S_IWUSR, NULL);
//ust//	if (!pentry)
//ust//		return -EBUSY;
//ust//	markers_loaded_cachep = KMEM_CACHE(ltt_active_marker, 0);

		ret = ltt_probe_register(&default_probe);
		BUG_ON(ret);
		ret = ltt_marker_connect("metadata", "core_marker_format",
					 DEFAULT_PROBE);
		BUG_ON(ret);
		ret = ltt_marker_connect("metadata", "core_marker_id", DEFAULT_PROBE);
		BUG_ON(ret);
//ust//	pentry->proc_fops = &ltt_fops;

		initialized = 1;
	}
}
//ust// module_init(marker_control_init);

static void __attribute__((destructor)) marker_control_exit(void)
{
	int ret;

//ust//	remove_proc_entry("ltt", NULL);
	ret = ltt_marker_disconnect("metadata", "core_marker_format",
				    DEFAULT_PROBE);
	BUG_ON(ret);
	ret = ltt_marker_disconnect("metadata", "core_marker_id",
				    DEFAULT_PROBE);
	BUG_ON(ret);
	ret = ltt_probe_unregister(&default_probe);
	BUG_ON(ret);
	disconnect_all_markers();
//ust//	kmem_cache_destroy(markers_loaded_cachep);
//ust//	marker_synchronize_unregister();
}
//ust// module_exit(marker_control_exit);

//ust// MODULE_LICENSE("GPL");
//ust// MODULE_AUTHOR("Mathieu Desnoyers");
//ust// MODULE_DESCRIPTION("Linux Trace Toolkit Marker Control");
