/*
 * Copyright (C) 2005,2006,2008 Mathieu Desnoyers (mathieu.desnoyers@polymtl.ca)
 * Copyright (C) 2009 Pierre-Marc Fournier
 *
 * This contains the definitions for the Linux Trace Toolkit tracer.
 *
 * Ported to userspace by Pierre-Marc Fournier.
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
 */

#ifndef _LTT_TRACER_H
#define _LTT_TRACER_H

#include <sys/types.h>
#include <stdarg.h>
#include <ust/marker.h>
#include <ust/probe.h>
#include <ust/core.h>
#include "channels.h"
#include "tracercore.h"
#include "tracerconst.h"
#include "buffers.h"

/* Number of bytes to log with a read/write event */
#define LTT_LOG_RW_SIZE			32L

/* Interval (in jiffies) at which the LTT per-CPU timer fires */
#define LTT_PERCPU_TIMER_INTERVAL	1

#ifndef LTT_ARCH_TYPE
#define LTT_ARCH_TYPE			LTT_ARCH_TYPE_UNDEFINED
#endif

#ifndef LTT_ARCH_VARIANT
#define LTT_ARCH_VARIANT		LTT_ARCH_VARIANT_NONE
#endif

struct ltt_active_marker;

/* Maximum number of callbacks per marker */
#define LTT_NR_CALLBACKS	10

struct ltt_serialize_closure;
struct ltt_probe_private_data;

struct ltt_serialize_closure {
	ltt_serialize_cb *callbacks;
	long cb_args[LTT_NR_CALLBACKS];
	unsigned int cb_idx;
};

extern size_t ltt_serialize_data(struct ust_buffer *buf, size_t buf_offset,
			struct ltt_serialize_closure *closure,
			void *serialize_private,
			unsigned int stack_pos_ctx, int *largest_align,
			const char *fmt, va_list *args);

struct ltt_probe_private_data {
	struct ust_trace *trace;	/*
					 * Target trace, for metadata
					 * or statedump.
					 */
	ltt_serialize_cb serializer;	/*
					 * Serialization function override.
					 */
	void *serialize_private;	/*
					 * Private data for serialization
					 * functions.
					 */
};

enum ltt_channels {
	LTT_CHANNEL_METADATA,
	LTT_CHANNEL_UST,
};

struct chan_info_struct {
	const char *name;
	unsigned int def_subbufsize;
	unsigned int def_subbufcount;
};

struct ltt_active_marker {
	struct cds_list_head node;		/* active markers list */
	const char *channel;
	const char *name;
	const char *format;
	struct ltt_available_probe *probe;
};

struct marker; //ust//
extern void ltt_vtrace(const struct marker *mdata, void *probe_data,
	struct registers *regs, void *call_data, const char *fmt, va_list *args);
extern void ltt_trace(const struct marker *mdata, void *probe_data,
	struct registers *regs, void *call_data, const char *fmt, ...);

/*
 * Unique ID assigned to each registered probe.
 */
enum marker_id {
	MARKER_ID_SET_MARKER_ID = 0,	/* Static IDs available (range 0-7) */
	MARKER_ID_SET_MARKER_FORMAT,
	MARKER_ID_COMPACT,		/* Compact IDs (range: 8-127)	    */
	MARKER_ID_DYNAMIC,		/* Dynamic IDs (range: 128-65535)   */
};

/* static ids 0-1 reserved for internal use. */
#define MARKER_CORE_IDS		2
static __inline__ enum marker_id marker_id_type(uint16_t id)
{
	if (id < MARKER_CORE_IDS)
		return (enum marker_id)id;
	else
		return MARKER_ID_DYNAMIC;
}

struct user_dbg_data {
	unsigned long avail_size;
	unsigned long write;
	unsigned long read;
};

struct ltt_trace_ops {
	/* First 32 bytes cache-hot cacheline */
	void (*wakeup_channel) (struct ust_channel *channel);
	int (*user_blocking) (struct ust_trace *trace,
				unsigned int index, size_t data_size,
				struct user_dbg_data *dbg);
	/* End of first 32 bytes cacheline */
	int (*create_dirs) (struct ust_trace *new_trace);
	void (*remove_dirs) (struct ust_trace *new_trace);
	int (*create_channel) (const char *trace_name,
				struct ust_trace *trace,
				const char *channel_name,
				struct ust_channel *channel,
				unsigned int subbuf_size,
				unsigned int n_subbufs, int overwrite);
	void (*finish_channel) (struct ust_channel *channel);
	void (*remove_channel) (struct ust_channel *channel);
	void (*user_errors) (struct ust_trace *trace,
				unsigned int index, size_t data_size,
				struct user_dbg_data *dbg, unsigned int cpu);
};

struct ltt_transport {
	char *name;
	struct module *owner;
	struct cds_list_head node;
	struct ltt_trace_ops ops;
};

enum trace_mode { LTT_TRACE_NORMAL, LTT_TRACE_FLIGHT, LTT_TRACE_HYBRID };

#define CHANNEL_FLAG_ENABLE	(1U<<0)
#define CHANNEL_FLAG_OVERWRITE	(1U<<1)

/* Per-trace information - each trace/flight recorder represented by one */
struct ust_trace {
	/* First 32 bytes cache-hot cacheline */
	struct cds_list_head list;
	struct ltt_trace_ops *ops;
	int active;
	/* Second 32 bytes cache-hot cacheline */
	struct ust_channel *channels;
	unsigned int nr_channels;
	u32 freq_scale;
	u64 start_freq;
	u64 start_tsc;
	unsigned long long start_monotonic;
	struct timeval		start_time;
	struct ltt_channel_setting *settings;
	struct {
		struct dentry			*trace_root;
	} dentry;
	struct urcu_ref urcu_ref; /* Each channel has a urcu_ref of the trace struct */
	struct ltt_transport *transport;
	struct urcu_ref ltt_transport_urcu_ref;
	char trace_name[NAME_MAX];
} ____cacheline_aligned;

/*
 * We use asm/timex.h : cpu_khz/HZ variable in here : we might have to deal
 * specifically with CPU frequency scaling someday, so using an interpolation
 * between the start and end of buffer values is not flexible enough. Using an
 * immediate frequency value permits to calculate directly the times for parts
 * of a buffer that would be before a frequency change.
 *
 * Keep the natural field alignment for _each field_ within this structure if
 * you ever add/remove a field from this header. Packed attribute is not used
 * because gcc generates poor code on at least powerpc and mips. Don't ever
 * let gcc add padding between the structure elements.
 */
struct ltt_subbuffer_header {
	uint64_t cycle_count_begin;	/* Cycle count at subbuffer start */
	uint64_t cycle_count_end;	/* Cycle count at subbuffer end */
	uint32_t magic_number;		/*
					 * Trace magic number.
					 * contains endianness information.
					 */
	uint8_t major_version;
	uint8_t minor_version;
	uint8_t arch_size;		/* Architecture pointer size */
	uint8_t alignment;		/* LTT data alignment */
	uint64_t start_time_sec;	/* NTP-corrected start time */
	uint64_t start_time_usec;
	uint64_t start_freq;		/*
					 * Frequency at trace start,
					 * used all along the trace.
					 */
	uint32_t freq_scale;		/* Frequency scaling (divisor) */
	uint32_t data_size;		/* Size of data in subbuffer */
	uint32_t sb_size;		/* Subbuffer size (including padding) */
	uint32_t events_lost;		/*
					 * Events lost in this subbuffer since
					 * the beginning of the trace.
					 * (may overflow)
					 */
	uint32_t subbuf_corrupt;	/*
					 * Corrupted (lost) subbuffers since
					 * the begginig of the trace.
					 * (may overflow)
					 */
	uint8_t header_end[0];		/* End of header */
};

/**
 * ltt_subbuffer_header_size - called on buffer-switch to a new sub-buffer
 *
 * Return header size without padding after the structure. Don't use packed
 * structure because gcc generates inefficient code on some architectures
 * (powerpc, mips..)
 */
static __inline__ size_t ltt_subbuffer_header_size(void)
{
	return offsetof(struct ltt_subbuffer_header, header_end);
}

extern size_t ltt_write_event_header_slow(struct ust_channel *channel,
               struct ust_buffer *buf, long buf_offset,
               u16 eID, u32 event_size,
               u64 tsc, unsigned int rflags);


/*
 * ltt_write_event_header
 *
 * Writes the event header to the offset (already aligned on 32-bits).
 *
 * @trace : trace to write to.
 * @channel : pointer to the channel structure..
 * @buf : buffer to write to.
 * @buf_offset : buffer offset to write to (aligned on 32 bits).
 * @eID : event ID
 * @event_size : size of the event, excluding the event header.
 * @tsc : time stamp counter.
 * @rflags : reservation flags.
 *
 * returns : offset where the event data must be written.
 */
static __inline__ size_t ltt_write_event_header(struct ust_channel *chan,
		struct ust_buffer *buf, long buf_offset,
		u16 eID, u32 event_size,
		u64 tsc, unsigned int rflags)
{
	struct ltt_event_header header;

	if (unlikely(rflags))
		goto slow_path;

	header.id_time = eID << LTT_TSC_BITS;
	header.id_time |= (u32)tsc & LTT_TSC_MASK;
	ust_buffers_write(buf, buf_offset, &header, sizeof(header));
	buf_offset += sizeof(header);

	return buf_offset;

slow_path:
	return ltt_write_event_header_slow(chan, buf, buf_offset,
				eID, event_size, tsc, rflags);
}

/*
 * Control channels :
 * control/metadata
 * control/interrupts
 * control/...
 *
 * cpu channel :
 * cpu
 */

#define LTT_METADATA_CHANNEL		"metadata_state"
#define LTT_UST_CHANNEL			"ust"

#define LTT_FLIGHT_PREFIX	"flight-"

/* Tracer properties */
//#define LTT_DEFAULT_SUBBUF_SIZE_LOW	134217728
#define LTT_DEFAULT_SUBBUF_SIZE_LOW	65536
//#define LTT_DEFAULT_SUBBUF_SIZE_LOW	4096
#define LTT_DEFAULT_N_SUBBUFS_LOW	2
//#define LTT_DEFAULT_SUBBUF_SIZE_MED	134217728
#define LTT_DEFAULT_SUBBUF_SIZE_MED	262144
//#define LTT_DEFAULT_SUBBUF_SIZE_MED	4096
#define LTT_DEFAULT_N_SUBBUFS_MED	2
//#define LTT_DEFAULT_SUBBUF_SIZE_HIGH	134217728
#define LTT_DEFAULT_SUBBUF_SIZE_HIGH	1048576
//#define LTT_DEFAULT_SUBBUF_SIZE_HIGH	4096
#define LTT_DEFAULT_N_SUBBUFS_HIGH	2
#define LTT_TRACER_MAGIC_NUMBER		0x00D6B7ED
#define LTT_TRACER_VERSION_MAJOR	2
#define LTT_TRACER_VERSION_MINOR	6

/**
 * ust_write_trace_header - Write trace header
 * @trace: Trace information
 * @header: Memory address where the information must be written to
 */
static __inline__ void ltt_write_trace_header(struct ust_trace *trace,
               struct ltt_subbuffer_header *header)
{
	header->magic_number = LTT_TRACER_MAGIC_NUMBER;
	header->major_version = LTT_TRACER_VERSION_MAJOR;
	header->minor_version = LTT_TRACER_VERSION_MINOR;
	header->arch_size = sizeof(void *);
	header->alignment = ltt_get_alignment();
	header->start_time_sec = trace->start_time.tv_sec;
	header->start_time_usec = trace->start_time.tv_usec;
	header->start_freq = trace->start_freq;
	header->freq_scale = trace->freq_scale;
}

static __inline__ int ust_get_cpu(void)
{
#ifndef UST_VALGRIND
	return sched_getcpu();
#else
	/* Valgrind does not support the sched_getcpu() vsyscall.
	 * It causes it to detect a segfault in the program and stop it.
	 * So if we want to check libust with valgrind, we have to refrain
	 * from using this call. TODO: it would probably be better to return
	 * other values too, to better test it.
	 */
	return 0;
#endif
}


/*
 * Size reserved for high priority events (interrupts, NMI, BH) at the end of a
 * nearly full buffer. User space won't use this last amount of space when in
 * blocking mode. This space also includes the event header that would be
 * written by this user space event.
 */
#define LTT_RESERVE_CRITICAL		4096

/* Register and unregister function pointers */

enum ltt_module_function {
	LTT_FUNCTION_RUN_FILTER,
	LTT_FUNCTION_FILTER_CONTROL,
	LTT_FUNCTION_STATEDUMP
};

extern void ltt_transport_register(struct ltt_transport *transport);
extern void ltt_transport_unregister(struct ltt_transport *transport);

/* Exported control function */

union ltt_control_args {
	struct {
		enum trace_mode mode;
		unsigned int subbuf_size_low;
		unsigned int n_subbufs_low;
		unsigned int subbuf_size_med;
		unsigned int n_subbufs_med;
		unsigned int subbuf_size_high;
		unsigned int n_subbufs_high;
	} new_trace;
};

extern int _ltt_trace_setup(const char *trace_name);
extern int ltt_trace_setup(const char *trace_name);
extern struct ust_trace *_ltt_trace_find_setup(const char *trace_name);
extern int ltt_trace_set_type(const char *trace_name, const char *trace_type);
extern int ltt_trace_set_channel_subbufsize(const char *trace_name,
		const char *channel_name, unsigned int size);
extern int ltt_trace_set_channel_subbufcount(const char *trace_name,
		const char *channel_name, unsigned int cnt);
extern int ltt_trace_set_channel_enable(const char *trace_name,
		const char *channel_name, unsigned int enable);
extern int ltt_trace_set_channel_overwrite(const char *trace_name,
		const char *channel_name, unsigned int overwrite);
extern int ltt_trace_alloc(const char *trace_name);
extern int ltt_trace_destroy(const char *trace_name, int drop);
extern int ltt_trace_start(const char *trace_name);
extern int ltt_trace_stop(const char *trace_name);

enum ltt_filter_control_msg {
	LTT_FILTER_DEFAULT_ACCEPT,
	LTT_FILTER_DEFAULT_REJECT
};

extern int ltt_filter_control(enum ltt_filter_control_msg msg,
		const char *trace_name);

extern struct dentry *get_filter_root(void);

extern void ltt_write_trace_header(struct ust_trace *trace,
		struct ltt_subbuffer_header *header);
extern void ltt_buffer_destroy(struct ust_channel *ltt_chan);

extern void ltt_core_register(int (*function)(u8, void *));

extern void ltt_core_unregister(void);

extern void ltt_release_trace(struct urcu_ref *urcu_ref);
extern void ltt_release_transport(struct urcu_ref *urcu_ref);

extern void ltt_dump_marker_state(struct ust_trace *trace);

extern void ltt_lock_traces(void);
extern void ltt_unlock_traces(void);

extern struct ust_trace *_ltt_trace_find(const char *trace_name);

#endif /* _LTT_TRACER_H */
