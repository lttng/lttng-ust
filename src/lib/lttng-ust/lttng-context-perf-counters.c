/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2009-2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng UST performance monitoring counters (perf-counters) integration.
 */

#define _LGPL_SOURCE
#include <limits.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <lttng/ust-arch.h>
#include <lttng/ust-events.h>
#include <lttng/ust-tracer.h>
#include <lttng/ust-ringbuffer-context.h>
#include <urcu/system.h>
#include <urcu/arch.h>
#include <urcu/rculist.h>
#include "common/macros.h"
#include <urcu/ref.h>
#include "common/logging.h"
#include <signal.h>
#include <urcu/tls-compat.h>
#include "perf_event.h"

#include "context-internal.h"
#include "lttng-tracer-core.h"
#include "lib/lttng-ust/events.h"

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
	int fd;					/* Perf FD */
};

struct lttng_perf_counter_thread {
	struct cds_list_head rcu_field_list;	/* RCU per-thread list of fields */
};

struct lttng_perf_counter_field {
	struct perf_event_attr attr;
	struct cds_list_head thread_field_list;	/* Per-field list of thread fields */
	char *name;
	struct lttng_ust_event_field *event_field;
};

static pthread_key_t perf_counter_key;

/*
 * lttng_perf_lock - Protect lttng-ust perf counter data structures
 *
 * Nests within the ust_lock, and therefore within the libc dl lock.
 * Therefore, we need to fixup the TLS before nesting into this lock.
 * Nests inside RCU bp read-side lock. Protects against concurrent
 * fork.
 */
static pthread_mutex_t ust_perf_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * Cancel state when grabbing the ust_perf_mutex. Saved when locking,
 * restored on unlock. Protected by ust_perf_mutex.
 */
static int ust_perf_saved_cancelstate;

/*
 * Track whether we are tracing from a signal handler nested on an
 * application thread.
 */
static DEFINE_URCU_TLS(int, ust_perf_mutex_nest);

/*
 * Force a read (imply TLS fixup for dlopen) of TLS variables.
 */
void lttng_ust_fixup_perf_counter_tls(void)
{
	asm volatile ("" : : "m" (URCU_TLS(ust_perf_mutex_nest)));
}

void lttng_perf_lock(void)
{
	sigset_t sig_all_blocked, orig_mask;
	int ret, oldstate;

	ret = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);
	if (ret) {
		ERR("pthread_setcancelstate: %s", strerror(ret));
	}
	sigfillset(&sig_all_blocked);
	ret = pthread_sigmask(SIG_SETMASK, &sig_all_blocked, &orig_mask);
	if (ret) {
		ERR("pthread_sigmask: %s", strerror(ret));
	}
	if (!URCU_TLS(ust_perf_mutex_nest)++) {
		/*
		 * Ensure the compiler don't move the store after the close()
		 * call in case close() would be marked as leaf.
		 */
		cmm_barrier();
		pthread_mutex_lock(&ust_perf_mutex);
		ust_perf_saved_cancelstate = oldstate;
	}
	ret = pthread_sigmask(SIG_SETMASK, &orig_mask, NULL);
	if (ret) {
		ERR("pthread_sigmask: %s", strerror(ret));
	}
}

void lttng_perf_unlock(void)
{
	sigset_t sig_all_blocked, orig_mask;
	int ret, newstate, oldstate;
	bool restore_cancel = false;

	sigfillset(&sig_all_blocked);
	ret = pthread_sigmask(SIG_SETMASK, &sig_all_blocked, &orig_mask);
	if (ret) {
		ERR("pthread_sigmask: %s", strerror(ret));
	}
	/*
	 * Ensure the compiler don't move the store before the close()
	 * call, in case close() would be marked as leaf.
	 */
	cmm_barrier();
	if (!--URCU_TLS(ust_perf_mutex_nest)) {
		newstate = ust_perf_saved_cancelstate;
		restore_cancel = true;
		pthread_mutex_unlock(&ust_perf_mutex);
	}
	ret = pthread_sigmask(SIG_SETMASK, &orig_mask, NULL);
	if (ret) {
		ERR("pthread_sigmask: %s", strerror(ret));
	}
	if (restore_cancel) {
		ret = pthread_setcancelstate(newstate, &oldstate);
		if (ret) {
			ERR("pthread_setcancelstate: %s", strerror(ret));
		}
	}
}

static
size_t perf_counter_get_size(void *priv __attribute__((unused)),
		size_t offset)
{
	size_t size = 0;

	size += lttng_ust_ring_buffer_align(offset, lttng_ust_rb_alignof(uint64_t));
	size += sizeof(uint64_t);
	return size;
}

static
uint64_t read_perf_counter_syscall(
		struct lttng_perf_counter_thread_field *thread_field)
{
	uint64_t count;

	if (caa_unlikely(thread_field->fd < 0))
		return 0;

	if (caa_unlikely(read(thread_field->fd, &count, sizeof(count))
				< sizeof(count)))
		return 0;

	return count;
}

#if defined(LTTNG_UST_ARCH_X86)

static
uint64_t rdpmc(unsigned int counter)
{
	unsigned int low, high;

	asm volatile("rdpmc" : "=a" (low), "=d" (high) : "c" (counter));

	return low | ((uint64_t) high) << 32;
}

static
bool has_rdpmc(struct perf_event_mmap_page *pc)
{
	if (caa_unlikely(!pc->cap_bit0_is_deprecated))
		return false;
	/* Since Linux kernel 3.12. */
	return pc->cap_user_rdpmc;
}

static
uint64_t arch_read_perf_counter(
		struct lttng_perf_counter_thread_field *thread_field)
{
	uint32_t seq, idx;
	uint64_t count;
	struct perf_event_mmap_page *pc = thread_field->pc;

	if (caa_unlikely(!pc))
		return 0;

	do {
		seq = CMM_LOAD_SHARED(pc->lock);
		cmm_barrier();

		idx = pc->index;
		if (caa_likely(has_rdpmc(pc) && idx)) {
			int64_t pmcval;

			pmcval = rdpmc(idx - 1);
			/* Sign-extend the pmc register result. */
			pmcval <<= 64 - pc->pmc_width;
			pmcval >>= 64 - pc->pmc_width;
			count = pc->offset + pmcval;
		} else {
			/* Fall-back on system call if rdpmc cannot be used. */
			return read_perf_counter_syscall(thread_field);
		}
		cmm_barrier();
	} while (CMM_LOAD_SHARED(pc->lock) != seq);

	return count;
}

static
int arch_perf_keep_fd(struct lttng_perf_counter_thread_field *thread_field)
{
	struct perf_event_mmap_page *pc = thread_field->pc;

	if (!pc)
		return 0;
	return !has_rdpmc(pc);
}

#else

/* Generic (slow) implementation using a read system call. */
static
uint64_t arch_read_perf_counter(
		struct lttng_perf_counter_thread_field *thread_field)
{
	return read_perf_counter_syscall(thread_field);
}

static
int arch_perf_keep_fd(struct lttng_perf_counter_thread_field *thread_field __attribute__((unused)))
{
	return 1;
}

#endif

static
int sys_perf_event_open(struct perf_event_attr *attr,
		pid_t pid, int cpu, int group_fd,
		unsigned long flags)
{
	return syscall(SYS_perf_event_open, attr, pid, cpu,
			group_fd, flags);
}

static
int open_perf_fd(struct perf_event_attr *attr)
{
	int fd;

	fd = sys_perf_event_open(attr, 0, -1, -1, 0);
	if (fd < 0)
		return -1;

	return fd;
}

static
void close_perf_fd(int fd)
{
	int ret;

	if (fd < 0)
		return;

	ret = close(fd);
	if (ret) {
		perror("Error closing LTTng-UST perf memory mapping FD");
	}
}

static void setup_perf(struct lttng_perf_counter_thread_field *thread_field)
{
	void *perf_addr;

	perf_addr = mmap(NULL, sizeof(struct perf_event_mmap_page),
			PROT_READ, MAP_SHARED, thread_field->fd, 0);
	if (perf_addr == MAP_FAILED)
		perf_addr = NULL;
	thread_field->pc = perf_addr;

	if (!arch_perf_keep_fd(thread_field)) {
		close_perf_fd(thread_field->fd);
		thread_field->fd = -1;
	}
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
	thread_field->fd = open_perf_fd(&perf_field->attr);
	if (thread_field->fd >= 0)
		setup_perf(thread_field);
	/*
	 * Note: thread_field->pc can be NULL if setup_perf() fails.
	 * Also, thread_field->fd can be -1 if open_perf_fd() fails.
	 */
	lttng_perf_lock();
	cds_list_add_rcu(&thread_field->rcu_field_node,
			&perf_thread->rcu_field_list);
	cds_list_add(&thread_field->thread_field_node,
			&perf_field->thread_field_list);
	lttng_perf_unlock();
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
uint64_t wrapper_perf_counter_read(void *priv)
{
	struct lttng_perf_counter_field *perf_field;
	struct lttng_perf_counter_thread_field *perf_thread_field;

	perf_field = (struct lttng_perf_counter_field *) priv;
	perf_thread_field = get_thread_field(perf_field);
	return arch_read_perf_counter(perf_thread_field);
}

static
void perf_counter_record(void *priv,
		 struct lttng_ust_ring_buffer_ctx *ctx,
		 struct lttng_ust_channel_buffer *chan)
{
	uint64_t value;

	value = wrapper_perf_counter_read(priv);
	chan->ops->event_write(ctx, &value, sizeof(value), lttng_ust_rb_alignof(value));
}

static
void perf_counter_get_value(void *priv,
		struct lttng_ust_ctx_value *value)
{
	value->u.s64 = wrapper_perf_counter_read(priv);
}

/* Called with perf lock held */
static
void lttng_destroy_perf_thread_field(
		struct lttng_perf_counter_thread_field *thread_field)
{
	close_perf_fd(thread_field->fd);
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

	lttng_perf_lock();
	cds_list_for_each_entry_safe(pos, p, &perf_thread->rcu_field_list,
			rcu_field_node)
		lttng_destroy_perf_thread_field(pos);
	lttng_perf_unlock();
	free(perf_thread);
}

/* Called with UST lock held */
static
void lttng_destroy_perf_counter_ctx_field(void *priv)
{
	struct lttng_perf_counter_field *perf_field;
	struct lttng_perf_counter_thread_field *pos, *p;

	perf_field = (struct lttng_perf_counter_field *) priv;
	free(perf_field->name);
	/*
	 * This put is performed when no threads can concurrently
	 * perform a "get" concurrently, thanks to urcu-bp grace
	 * period. Holding the lttng perf lock protects against
	 * concurrent modification of the per-thread thread field
	 * list.
	 */
	lttng_perf_lock();
	cds_list_for_each_entry_safe(pos, p, &perf_field->thread_field_list,
			thread_field_node)
		lttng_destroy_perf_thread_field(pos);
	lttng_perf_unlock();
	free(perf_field->event_field);
	free(perf_field);
}

#ifdef LTTNG_UST_ARCH_ARMV7

static
int perf_get_exclude_kernel(void)
{
	return 0;
}

#else /* LTTNG_UST_ARCH_ARMV7 */

static
int perf_get_exclude_kernel(void)
{
	return 1;
}

#endif /* LTTNG_UST_ARCH_ARMV7 */

static const struct lttng_ust_type_common *ust_type =
	lttng_ust_static_type_integer(sizeof(uint64_t) * CHAR_BIT,
			lttng_ust_rb_alignof(uint64_t) * CHAR_BIT,
			lttng_ust_is_signed_type(uint64_t),
			LTTNG_UST_BYTE_ORDER, 10);

/* Called with UST lock held */
int lttng_add_perf_counter_to_ctx(uint32_t type,
				uint64_t config,
				const char *name,
				struct lttng_ust_ctx **ctx)
{
	struct lttng_ust_ctx_field ctx_field;
	struct lttng_ust_event_field *event_field;
	struct lttng_perf_counter_field *perf_field;
	char *name_alloc;
	int ret;

	if (lttng_find_context(*ctx, name)) {
		ret = -EEXIST;
		goto find_error;
	}
	name_alloc = strdup(name);
	if (!name_alloc) {
		ret = -ENOMEM;
		goto name_alloc_error;
	}
	event_field = zmalloc(sizeof(*event_field));
	if (!event_field) {
		ret = -ENOMEM;
		goto event_field_alloc_error;
	}
	event_field->name = name_alloc;
	event_field->type = ust_type;

	perf_field = zmalloc(sizeof(*perf_field));
	if (!perf_field) {
		ret = -ENOMEM;
		goto perf_field_alloc_error;
	}
	perf_field->attr.type = type;
	perf_field->attr.config = config;
	perf_field->attr.exclude_kernel = perf_get_exclude_kernel();
	CDS_INIT_LIST_HEAD(&perf_field->thread_field_list);
	perf_field->name = name_alloc;
	perf_field->event_field = event_field;

	/* Ensure that this perf counter can be used in this process. */
	ret = open_perf_fd(&perf_field->attr);
	if (ret < 0) {
		ret = -ENODEV;
		goto setup_error;
	}
	close_perf_fd(ret);

	ctx_field.event_field = event_field;
	ctx_field.get_size = perf_counter_get_size;
	ctx_field.record = perf_counter_record;
	ctx_field.get_value = perf_counter_get_value;
	ctx_field.destroy = lttng_destroy_perf_counter_ctx_field;
	ctx_field.priv = perf_field;

	ret = lttng_ust_context_append(ctx, &ctx_field);
	if (ret) {
		ret = -ENOMEM;
		goto append_context_error;
	}
	return 0;

append_context_error:
setup_error:
	free(perf_field);
perf_field_alloc_error:
	free(event_field);
event_field_alloc_error:
	free(name_alloc);
name_alloc_error:
find_error:
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
