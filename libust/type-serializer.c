/**
 * ltt-type-serializer.c
 *
 * LTTng specialized type serializer.
 *
 * Copyright Mathieu Desnoyers, 2008.
 *
 * Dual LGPL v2.1/GPL v2 license.
 */

/* This file contains functions for tracepoint custom probes support. */

#include <urcu/rculist.h>
#include <ust/type-serializer.h>
#include <ust/core.h>
#include <ust/clock.h>
#include "tracer.h"

notrace
void _ltt_specialized_trace(const struct marker *mdata, void *probe_data,
		void *serialize_private, unsigned int data_size,
		unsigned int largest_align)
{
	int ret;
	uint16_t eID;
	size_t slot_size;
	unsigned int chan_index;
	struct ust_buffer *buf;
	struct ust_channel *chan;
	struct ust_trace *trace;
	u64 tsc;
	long buf_offset;
	int cpu;
	unsigned int rflags;

	/*
	 * If we get here, it's probably because we have useful work to do.
	 */
	if (unlikely(ltt_traces.num_active_traces == 0))
		return;

	rcu_read_lock();
	cpu = ust_get_cpu();

	/* Force volatile access. */
	CMM_STORE_SHARED(ltt_nesting, CMM_LOAD_SHARED(ltt_nesting) + 1);

	/*
	 * asm volatile and "memory" clobber prevent the compiler from moving
	 * instructions out of the ltt nesting count. This is required to ensure
	 * that probe side-effects which can cause recursion (e.g. unforeseen
	 * traps, divisions by 0, ...) are triggered within the incremented
	 * nesting count section.
	 */
	cmm_barrier();
	eID = mdata->event_id;
	chan_index = mdata->channel_id;

	/*
	 * Iterate on each trace, typically small number of active traces,
	 * list iteration with prefetch is usually slower.
	 */
	cds_list_for_each_entry_rcu(trace, &ltt_traces.head, list) {
		if (unlikely(!trace->active))
			continue;
//ust//		if (unlikely(!ltt_run_filter(trace, eID)))
//ust//			continue;
#ifdef CONFIG_LTT_DEBUG_EVENT_SIZE
		rflags = LTT_RFLAG_ID_SIZE;
#else
		if (unlikely(eID >= LTT_FREE_EVENTS))
			rflags = LTT_RFLAG_ID;
		else
			rflags = 0;
#endif
		/*
		 * Skip channels added after trace creation.
		 */
		if (unlikely(chan_index >= trace->nr_channels))
			continue;
		chan = &trace->channels[chan_index];
		if (!chan->active)
			continue;

		/* If a new cpu was plugged since the trace was started, we did
		 * not add it to the trace, and therefore we write the event to
		 * cpu 0.
		 */
		if(cpu >= chan->n_cpus) {
			cpu = 0;
		}

		/* reserve space : header and data */
		ret = ltt_reserve_slot(chan, trace, data_size, largest_align,
				       cpu, &buf, &slot_size, &buf_offset, &tsc,
				       &rflags);
		if (unlikely(ret < 0))
			continue; /* buffer full */

		/* Out-of-order write : header and data */
		buf_offset = ltt_write_event_header(chan, buf,
						    buf_offset, eID, data_size,
						    tsc, rflags);
		if (data_size) {
			buf_offset += ltt_align(buf_offset, largest_align);
			ust_buffers_write(buf, buf_offset,
					serialize_private, data_size);
			buf_offset += data_size;
		}
		/* Out-of-order commit */
		ltt_commit_slot(chan, buf, buf_offset, data_size, slot_size);
	}
	/*
	 * asm volatile and "memory" clobber prevent the compiler from moving
	 * instructions out of the ltt nesting count. This is required to ensure
	 * that probe side-effects which can cause recursion (e.g. unforeseen
	 * traps, divisions by 0, ...) are triggered within the incremented
	 * nesting count section.
	 */
	cmm_barrier();
	CMM_STORE_SHARED(ltt_nesting, CMM_LOAD_SHARED(ltt_nesting) - 1);
	rcu_read_unlock();
}
