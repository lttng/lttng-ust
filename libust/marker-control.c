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
 */

/* This file contains a high-level API for activating and deactivating ust_markers,
 * and making sure ust_markers in a given library can be released when the library
 * is unloaded.
 */

#include <ctype.h>
#include <stdlib.h>

#include "tracer.h"
#include "usterr_signal_safe.h"

#define DEFAULT_CHANNEL "cpu"
#define DEFAULT_PROBE "default"

static int initialized;

CDS_LIST_HEAD(probes_list);

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

//ust//static struct kmem_cache *ust_markers_loaded_cachep;
static CDS_LIST_HEAD(ust_markers_loaded_list);
/*
 * List sorted by name strcmp order.
 */
static CDS_LIST_HEAD(probes_registered_list);

static struct ltt_available_probe *get_probe_from_name(const char *pname)
{
	struct ltt_available_probe *iter;
	int comparison, found = 0;

	if (!pname)
		pname = DEFAULT_PROBE;
	cds_list_for_each_entry(iter, &probes_registered_list, node) {
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

static void get_ust_marker_string(char *buf, char **start,
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

	pthread_mutex_lock(&probes_mutex);
	cds_list_for_each_entry_reverse(iter, &probes_registered_list, node) {
		comparison = strcmp(pdata->name, iter->name);
		if (!comparison) {
			ret = -EBUSY;
			goto end;
		} else if (comparison > 0) {
			/* We belong to the location right after iter. */
			cds_list_add(&pdata->node, &iter->node);
			goto end;
		}
	}
	/* Should be added at the head of the list */
	cds_list_add(&pdata->node, &probes_registered_list);
end:
	pthread_mutex_unlock(&probes_mutex);
	return ret;
}

/*
 * Called when a probe does not want to be called anymore.
 */
int ltt_probe_unregister(struct ltt_available_probe *pdata)
{
	int ret = 0;
	struct ltt_active_ust_marker *amark, *tmp;

	pthread_mutex_lock(&probes_mutex);
	cds_list_for_each_entry_safe(amark, tmp, &ust_markers_loaded_list, node) {
		if (amark->probe == pdata) {
			ret = ust_marker_probe_unregister_private_data(
				pdata->probe_func, amark);
			if (ret)
				goto end;
			cds_list_del(&amark->node);
			free(amark);
		}
	}
	cds_list_del(&pdata->node);
end:
	pthread_mutex_unlock(&probes_mutex);
	return ret;
}

/*
 * Connect ust_marker "mname" to probe "pname".
 * Only allow _only_ probe instance to be connected to a ust_marker.
 */
int ltt_ust_marker_connect(const char *channel, const char *mname,
		       const char *pname)

{
	int ret;
	struct ltt_active_ust_marker *pdata;
	struct ltt_available_probe *probe;

	ltt_lock_traces();
	pthread_mutex_lock(&probes_mutex);
	probe = get_probe_from_name(pname);
	if (!probe) {
		ret = -ENOENT;
		goto end;
	}
	pdata = ust_marker_get_private_data(channel, mname, probe->probe_func, 0);
	if (pdata && !IS_ERR(pdata)) {
		ret = -EEXIST;
		goto end;
	}
	pdata = zmalloc(sizeof(struct ltt_active_ust_marker));
	if (!pdata) {
		ret = -ENOMEM;
		goto end;
	}
	pdata->probe = probe;
	/*
	 * ID has priority over channel in case of conflict.
	 */
	ret = ust_marker_probe_register(channel, mname, NULL,
		probe->probe_func, pdata);
	if (ret)
		free(pdata);
	else
		cds_list_add(&pdata->node, &ust_markers_loaded_list);
end:
	pthread_mutex_unlock(&probes_mutex);
	ltt_unlock_traces();
	return ret;
}

/*
 * Disconnect ust_marker "mname", probe "pname".
 */
int ltt_ust_marker_disconnect(const char *channel, const char *mname,
			  const char *pname)
{
	struct ltt_active_ust_marker *pdata;
	struct ltt_available_probe *probe;
	int ret = 0;

	pthread_mutex_lock(&probes_mutex);
	probe = get_probe_from_name(pname);
	if (!probe) {
		ret = -ENOENT;
		goto end;
	}
	pdata = ust_marker_get_private_data(channel, mname, probe->probe_func, 0);
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
	ret = ust_marker_probe_unregister(channel, mname, probe->probe_func, pdata);
	if (ret)
		goto end;
	else {
		cds_list_del(&pdata->node);
		free(pdata);
	}
end:
	pthread_mutex_unlock(&probes_mutex);
	return ret;
}

static void disconnect_all_ust_markers(void)
{
	struct ltt_active_ust_marker *pdata, *tmp;

	cds_list_for_each_entry_safe(pdata, tmp, &ust_markers_loaded_list, node) {
		ust_marker_probe_unregister_private_data(pdata->probe->probe_func,
			pdata);
		cds_list_del(&pdata->node);
		free(pdata);
	}
}

void __attribute__((constructor)) init_ust_marker_control(void)
{
	if (!initialized) {
		int ret;

		init_ust_marker();
		ret = ltt_probe_register(&default_probe);
		BUG_ON(ret);
		ret = ltt_ust_marker_connect("metadata", "core_marker_format",
					 DEFAULT_PROBE);
		BUG_ON(ret);
		ret = ltt_ust_marker_connect("metadata", "core_marker_id", DEFAULT_PROBE);
		BUG_ON(ret);
		initialized = 1;
	}
}

static void __attribute__((destructor)) ust_marker_control_exit(void)
{
	int ret;

	ret = ltt_ust_marker_disconnect("metadata", "core_marker_format",
				    DEFAULT_PROBE);
	BUG_ON(ret);
	ret = ltt_ust_marker_disconnect("metadata", "core_marker_id",
				    DEFAULT_PROBE);
	BUG_ON(ret);
	ret = ltt_probe_unregister(&default_probe);
	BUG_ON(ret);
	disconnect_all_ust_markers();
	ust_marker_synchronize_unregister();
}
