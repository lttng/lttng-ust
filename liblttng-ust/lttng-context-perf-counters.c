/*
 * lttng-context-perf-counters.c
 *
 * LTTng UST performance monitoring counters (perf-counters) integration.
 *
 * Copyright (C) 2009-2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; only
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <lttng/ust-events.h>
#include <lttng/ust-tracer.h>
#include <lttng/ringbuffer-config.h>
#include <urcu/system.h>
#include <urcu/arch.h>
#include <urcu/rculist.h>
#include <helper.h>
#include <urcu/ref.h>
#include <usterr-signal-safe.h>
#include <signal.h>
#include "lttng-tracer-core.h"

/*
 * We use a global perf counter key and iterate on per-thread RCU lists
 * of fields in the fast path, even though this is not strictly speaking
 * what would provide the best fast-path complexity, to ensure teardown
 * of sessions vs thread exit is handled racelessly.
 *
 * Updates and traversals of thread_list are protected by UST lock.
 * Updates to rcu_field_list are protected by UST lock.
 */

struct lttng_perf_counter_thread_field {
	struct lttng_perf_counter_field *field;	/* Back reference */
	struct perf_event_mmap_page *pc;
	struct cds_list_head thread_field_node;	/* Per-field list of thread fields (node) */
	struct cds_list_head rcu_field_node;	/* RCU per-thread list of fields (node) */
};

struct lttng_perf_counter_thread {
	struct cds_list_head rcu_field_list;	/* RCU per-thread list of fields */
};

struct lttng_perf_counter_field {
	struct perf_event_attr attr;
	struct cds_list_head thread_field_list;	/* Per-field list of thread fields */
};

static pthread_key_t perf_counter_key;

static
size_t perf_counter_get_size(size_t offset)
{
	size_t size = 0;

	size += lib_ring_buffer_align(offset, lttng_alignof(uint64_t));
	size += sizeof(uint64_t);
	return size;
}

#if defined(__x86_64__) || defined(__i386__)

static
uint64_t rdpmc(unsigned int counter)
{
	unsigned int low, high;

	asm volatile("rdpmc" : "=a" (low), "=d" (high) : "c" (counter));

	return low | ((uint64_t) high) << 32;
}

#else /* defined(__x86_64__) || defined(__i386__) */

#error "Perf event counters are only supported on x86 so far."

#endif /* #else defined(__x86_64__) || defined(__i386__) */

static
uint64_t read_perf_counter(struct perf_event_mmap_page *pc)
{
	uint32_t seq, idx;
	uint64_t count;

	if (caa_unlikely(!pc))
		return 0;

	do {
		seq = CMM_LOAD_SHARED(pc->lock);
		cmm_barrier();

		idx = pc->index;
		if (idx)
			count = pc->offset + rdpmc(idx - 1);
		else
			count = 0;

		cmm_barrier();
	} while (CMM_LOAD_SHARED(pc->lock) != seq);

	return count;
}

static
int sys_perf_event_open(struct perf_event_attr *attr,
		pid_t pid, int cpu, int group_fd,
		unsigned long flags)
{
	return syscall(SYS_perf_event_open, attr, pid, cpu,
			group_fd, flags);
}

static
struct perf_event_mmap_page *setup_perf(struct perf_event_attr *attr)
{
	void *perf_addr;
	int fd, ret;

	fd = sys_perf_event_open(attr, 0, -1, -1, 0);
	if (fd < 0)
		return NULL;

	perf_addr = mmap(NULL, sizeof(struct perf_event_mmap_page),
			PROT_READ, MAP_SHARED, fd, 0);
	if (perf_addr == MAP_FAILED)
		return NULL;
	ret = close(fd);
	if (ret) {
		perror("Error closing LTTng-UST perf memory mapping FD");
	}
	return perf_addr;
}

static
void unmap_perf_page(struct perf_event_mmap_page *pc)
{
	int ret;

	if (!pc)
		return;
	ret = munmap(pc, sizeof(struct perf_event_mmap_page));
	if (ret < 0) {
		PERROR("Error in munmap");
		abort();
	}
}

static
struct lttng_perf_counter_thread *alloc_perf_counter_thread(void)
{
	struct lttng_perf_counter_thread *perf_thread;
	sigset_t newmask, oldmask;
	int ret;

	ret = sigfillset(&newmask);
	if (ret)
		abort();
	ret = pthread_sigmask(SIG_BLOCK, &newmask, &oldmask);
	if (ret)
		abort();
	/* Check again with signals disabled */
	perf_thread = pthread_getspecific(perf_counter_key);
	if (perf_thread)
		goto skip;
	perf_thread = zmalloc(sizeof(*perf_thread));
	if (!perf_thread)
		abort();
	CDS_INIT_LIST_HEAD(&perf_thread->rcu_field_list);
	ret = pthread_setspecific(perf_counter_key, perf_thread);
	if (ret)
		abort();
skip:
	ret = pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
	if (ret)
		abort();
	return perf_thread;
}

static
struct lttng_perf_counter_thread_field *
	add_thread_field(struct lttng_perf_counter_field *perf_field,
		struct lttng_perf_counter_thread *perf_thread)
{
	struct lttng_perf_counter_thread_field *thread_field;
	sigset_t newmask, oldmask;
	int ret;

	ret = sigfillset(&newmask);
	if (ret)
		abort();
	ret = pthread_sigmask(SIG_BLOCK, &newmask, &oldmask);
	if (ret)
		abort();
	/* Check again with signals disabled */
	cds_list_for_each_entry_rcu(thread_field, &perf_thread->rcu_field_list,
			rcu_field_node) {
		if (thread_field->field == perf_field)
			goto skip;
	}
	thread_field = zmalloc(sizeof(*thread_field));
	if (!thread_field)
		abort();
	thread_field->field = perf_field;
	thread_field->pc = setup_perf(&perf_field->attr);
	/* Note: thread_field->pc can be NULL if setup_perf() fails. */
	ust_lock_nocheck();
	cds_list_add_rcu(&thread_field->rcu_field_node,
			&perf_thread->rcu_field_list);
	cds_list_add(&thread_field->thread_field_node,
			&perf_field->thread_field_list);
	ust_unlock();
skip:
	ret = pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
	if (ret)
		abort();
	return thread_field;
}

static
struct lttng_perf_counter_thread_field *
		get_thread_field(struct lttng_perf_counter_field *field)
{
	struct lttng_perf_counter_thread *perf_thread;
	struct lttng_perf_counter_thread_field *thread_field;

	perf_thread = pthread_getspecific(perf_counter_key);
	if (!perf_thread)
		perf_thread = alloc_perf_counter_thread();
	cds_list_for_each_entry_rcu(thread_field, &perf_thread->rcu_field_list,
			rcu_field_node) {
		if (thread_field->field == field)
			return thread_field;
	}
	/* perf_counter_thread_field not found, need to add one */
	return add_thread_field(field, perf_thread);
}

static
uint64_t wrapper_perf_counter_read(struct lttng_ctx_field *field)
{
	struct lttng_perf_counter_field *perf_field;
	struct lttng_perf_counter_thread_field *perf_thread_field;

	perf_field = field->u.perf_counter;
	perf_thread_field = get_thread_field(perf_field);
	return read_perf_counter(perf_thread_field->pc);
}

static
void perf_counter_record(struct lttng_ctx_field *field,
		 struct lttng_ust_lib_ring_buffer_ctx *ctx,
		 struct lttng_channel *chan)
{
	uint64_t value;

	value = wrapper_perf_counter_read(field);
	lib_ring_buffer_align_ctx(ctx, lttng_alignof(value));
	chan->ops->event_write(ctx, &value, sizeof(value));
}

static
void perf_counter_get_value(struct lttng_ctx_field *field,
		union lttng_ctx_value *value)
{
	uint64_t v;

	v = wrapper_perf_counter_read(field);
	value->s64 = v;
}

/* Called with UST lock held */
static
void lttng_destroy_perf_thread_field(
		struct lttng_perf_counter_thread_field *thread_field)
{
	unmap_perf_page(thread_field->pc);
	cds_list_del_rcu(&thread_field->rcu_field_node);
	cds_list_del(&thread_field->thread_field_node);
	free(thread_field);
}

static
void lttng_destroy_perf_thread_key(void *_key)
{
	struct lttng_perf_counter_thread *perf_thread = _key;
	struct lttng_perf_counter_thread_field *pos, *p;

	ust_lock_nocheck();
	cds_list_for_each_entry_safe(pos, p, &perf_thread->rcu_field_list,
			rcu_field_node)
		lttng_destroy_perf_thread_field(pos);
	ust_unlock();
	free(perf_thread);
}

/* Called with UST lock held */
static
void lttng_destroy_perf_counter_field(struct lttng_ctx_field *field)
{
	struct lttng_perf_counter_field *perf_field;
	struct lttng_perf_counter_thread_field *pos, *p;

	free((char *) field->event_field.name);
	perf_field = field->u.perf_counter;
	/*
	 * This put is performed when no threads can concurrently
	 * perform a "get" concurrently, thanks to urcu-bp grace
	 * period.
	 */
	cds_list_for_each_entry_safe(pos, p, &perf_field->thread_field_list,
			thread_field_node)
		lttng_destroy_perf_thread_field(pos);
	free(perf_field);
}

/* Called with UST lock held */
int lttng_add_perf_counter_to_ctx(uint32_t type,
				uint64_t config,
				const char *name,
				struct lttng_ctx **ctx)
{
	struct lttng_ctx_field *field;
	struct lttng_perf_counter_field *perf_field;
	struct perf_event_mmap_page *tmp_pc;
	char *name_alloc;
	int ret;

	name_alloc = strdup(name);
	if (!name_alloc) {
		ret = -ENOMEM;
		goto name_alloc_error;
	}
	perf_field = zmalloc(sizeof(*perf_field));
	if (!perf_field) {
		ret = -ENOMEM;
		goto perf_field_alloc_error;
	}
	field = lttng_append_context(ctx);
	if (!field) {
		ret = -ENOMEM;
		goto append_context_error;
	}
	if (lttng_find_context(*ctx, name_alloc)) {
		ret = -EEXIST;
		goto find_error;
	}

	field->destroy = lttng_destroy_perf_counter_field;

	field->event_field.name = name_alloc;
	field->event_field.type.atype = atype_integer;
	field->event_field.type.u.basic.integer.size =
			sizeof(uint64_t) * CHAR_BIT;
	field->event_field.type.u.basic.integer.alignment =
			lttng_alignof(uint64_t) * CHAR_BIT;
	field->event_field.type.u.basic.integer.signedness =
			lttng_is_signed_type(uint64_t);
	field->event_field.type.u.basic.integer.reverse_byte_order = 0;
	field->event_field.type.u.basic.integer.base = 10;
	field->event_field.type.u.basic.integer.encoding = lttng_encode_none;
	field->get_size = perf_counter_get_size;
	field->record = perf_counter_record;
	field->get_value = perf_counter_get_value;

	perf_field->attr.type = type;
	perf_field->attr.config = config;
	perf_field->attr.exclude_kernel = 1;
	CDS_INIT_LIST_HEAD(&perf_field->thread_field_list);
	field->u.perf_counter = perf_field;

	/* Ensure that this perf counter can be used in this process. */
	tmp_pc = setup_perf(&perf_field->attr);
	if (!tmp_pc) {
		ret = -ENODEV;
		goto setup_error;
	}
	unmap_perf_page(tmp_pc);

	/*
	 * Contexts can only be added before tracing is started, so we
	 * don't have to synchronize against concurrent threads using
	 * the field here.
	 */

	return 0;

setup_error:
find_error:
	lttng_remove_context_field(ctx, field);
append_context_error:
	free(perf_field);
perf_field_alloc_error:
	free(name_alloc);
name_alloc_error:
	return ret;
}

int lttng_perf_counter_init(void)
{
	int ret;

	ret = pthread_key_create(&perf_counter_key,
			lttng_destroy_perf_thread_key);
	if (ret)
		ret = -ret;
	return ret;
}

void lttng_perf_counter_exit(void)
{
	int ret;

	ret = pthread_key_delete(perf_counter_key);
	if (ret) {
		errno = ret;
		PERROR("Error in pthread_key_delete");
	}
}
