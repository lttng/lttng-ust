/*
 * LTT core in-kernel infrastructure.
 *
 * Copyright 2006 - Mathieu Desnoyers mathieu.desnoyers@polymtl.ca
 *
 * Distributed under the GPL license
 */

//ust// #include <linux/ltt-core.h>
//ust// #include <linux/percpu.h>
//ust// #include <linux/module.h>
//ust// #include <linux/debugfs.h>
#include "tracercore.h"

/* Traces structures */
struct ltt_traces ltt_traces = {
	.setup_head = LIST_HEAD_INIT(ltt_traces.setup_head),
	.head = LIST_HEAD_INIT(ltt_traces.head),
};
//ust// EXPORT_SYMBOL(ltt_traces);

/* Traces list writer locking */
static DEFINE_MUTEX(ltt_traces_mutex);

/* dentry of ltt's root dir */
//ust// static struct dentry *ltt_root_dentry;
//ust// struct dentry *get_ltt_root(void)
//ust// {
//ust// 	if (!ltt_root_dentry) {
//ust// 	ltt_root_dentry = debugfs_create_dir(LTT_ROOT, NULL);
//ust// 		if (!ltt_root_dentry)
//ust// 			printk(KERN_ERR "LTT : create ltt root dir failed\n");
//ust// 	}
//ust// 	return ltt_root_dentry;
//ust// }
//ust// EXPORT_SYMBOL_GPL(get_ltt_root);

void ltt_lock_traces(void)
{
	mutex_lock(&ltt_traces_mutex);
}
//ust// EXPORT_SYMBOL_GPL(ltt_lock_traces);

void ltt_unlock_traces(void)
{
	mutex_unlock(&ltt_traces_mutex);
}
//ust// EXPORT_SYMBOL_GPL(ltt_unlock_traces);

//ust// DEFINE_PER_CPU(unsigned int, ltt_nesting);
//ust// EXPORT_PER_CPU_SYMBOL(ltt_nesting);
unsigned int ltt_nesting;

int ltt_run_filter_default(void *trace, uint16_t eID)
{
	return 1;
}

/* This function pointer is protected by a trace activation check */
ltt_run_filter_functor ltt_run_filter = ltt_run_filter_default;
//ust// EXPORT_SYMBOL_GPL(ltt_run_filter);

void ltt_filter_register(ltt_run_filter_functor func)
{
	ltt_run_filter = func;
}
//ust// EXPORT_SYMBOL_GPL(ltt_filter_register);

void ltt_filter_unregister(void)
{
	ltt_run_filter = ltt_run_filter_default;
}
//ust// EXPORT_SYMBOL_GPL(ltt_filter_unregister);
