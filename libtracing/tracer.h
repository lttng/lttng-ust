/*
 * Copyright (C) 2005,2006,2008 Mathieu Desnoyers (mathieu.desnoyers@polymtl.ca)
 *
 * This contains the definitions for the Linux Trace Toolkit tracer.
 */

#ifndef _LTT_TRACER_H
#define _LTT_TRACER_H

//ust// #include <stdarg.h>
//ust// #include <linux/types.h>
//ust// #include <linux/limits.h>
//ust// #include <linux/list.h>
//ust// #include <linux/cache.h>
//ust// #include <linux/kernel.h>
//ust// #include <linux/timex.h>
//ust// #include <linux/wait.h>
//ust// #include <linux/ltt-relay.h>
//ust// #include <linux/ltt-channels.h>
//ust// #include <linux/ltt-core.h>
//ust// #include <linux/marker.h>
//ust// #include <linux/trace-clock.h>
//ust// #include <asm/atomic.h>
//ust// #include <asm/local.h>
#include <sys/types.h>
#include <stdarg.h>
#include "relay.h"
#include "list.h"
#include "kernelcompat.h"
#include "channels.h"

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

/* Serialization callback '%k' */
typedef size_t (*ltt_serialize_cb)(struct rchan_buf *buf, size_t buf_offset,
			struct ltt_serialize_closure *closure,
			void *serialize_private, int *largest_align,
			const char *fmt, va_list *args);

struct ltt_serialize_closure {
	ltt_serialize_cb *callbacks;
	long cb_args[LTT_NR_CALLBACKS];
	unsigned int cb_idx;
};

size_t ltt_serialize_data(struct rchan_buf *buf, size_t buf_offset,
			struct ltt_serialize_closure *closure,
			void *serialize_private,
			int *largest_align, const char *fmt, va_list *args);

//ust// struct ltt_available_probe {
//ust// 	const char *name;		/* probe name */
//ust// 	const char *format;
//ust// 	marker_probe_func *probe_func;
//ust// 	ltt_serialize_cb callbacks[LTT_NR_CALLBACKS];
//ust// 	struct list_head node;		/* registered probes list */
//ust// };

struct ltt_probe_private_data {
	struct ltt_trace_struct *trace;	/*
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

struct ltt_active_marker {
	struct list_head node;		/* active markers list */
	const char *channel;
	const char *name;
	const char *format;
	struct ltt_available_probe *probe;
};

struct marker; //ust//
extern void ltt_vtrace(const struct marker *mdata, void *probe_data,
	void *call_data, const char *fmt, va_list *args);
extern void ltt_trace(const struct marker *mdata, void *probe_data,
	void *call_data, const char *fmt, ...);

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
static inline enum marker_id marker_id_type(uint16_t id)
{
	if (id < MARKER_CORE_IDS)
		return (enum marker_id)id;
	else
		return MARKER_ID_DYNAMIC;
}

//ust// #ifdef CONFIG_LTT

struct user_dbg_data {
	unsigned long avail_size;
	unsigned long write;
	unsigned long read;
};

struct ltt_trace_ops {
	/* First 32 bytes cache-hot cacheline */
	int (*reserve_slot) (struct ltt_trace_struct *trace,
				struct ltt_channel_struct *channel,
				void **transport_data, size_t data_size,
				size_t *slot_size, long *buf_offset, u64 *tsc,
				unsigned int *rflags,
				int largest_align,
				int cpu);
	void (*commit_slot) (struct ltt_channel_struct *channel,
				void **transport_data, long buf_offset,
				size_t slot_size);
	void (*wakeup_channel) (struct ltt_channel_struct *ltt_channel);
	int (*user_blocking) (struct ltt_trace_struct *trace,
				unsigned int index, size_t data_size,
				struct user_dbg_data *dbg);
//ust// 	/* End of first 32 bytes cacheline */
//ust// 	int (*create_dirs) (struct ltt_trace_struct *new_trace);
//ust// 	void (*remove_dirs) (struct ltt_trace_struct *new_trace);
 	int (*create_channel) (const char *trace_name,
 				struct ltt_trace_struct *trace,
 				struct dentry *dir, const char *channel_name,
 				struct ltt_channel_struct *ltt_chan,
 				unsigned int subbuf_size,
 				unsigned int n_subbufs, int overwrite);
 	void (*finish_channel) (struct ltt_channel_struct *channel);
 	void (*remove_channel) (struct ltt_channel_struct *channel);
 	void (*user_errors) (struct ltt_trace_struct *trace,
 				unsigned int index, size_t data_size,
 				struct user_dbg_data *dbg, int cpu);
//ust// #ifdef CONFIG_HOTPLUG_CPU
//ust// 	int (*handle_cpuhp) (struct notifier_block *nb,
//ust// 				unsigned long action, void *hcpu,
//ust// 				struct ltt_trace_struct *trace);
//ust// #endif
} ____cacheline_aligned;

struct ltt_transport {
	char *name;
	struct module *owner;
	struct list_head node;
	struct ltt_trace_ops ops;
};

enum trace_mode { LTT_TRACE_NORMAL, LTT_TRACE_FLIGHT, LTT_TRACE_HYBRID };

#define CHANNEL_FLAG_ENABLE	(1U<<0)
#define CHANNEL_FLAG_OVERWRITE	(1U<<1)

/* Per-trace information - each trace/flight recorder represented by one */
struct ltt_trace_struct {
	/* First 32 bytes cache-hot cacheline */
	struct list_head list;
	struct ltt_trace_ops *ops;
	int active;
	/* Second 32 bytes cache-hot cacheline */
	struct ltt_channel_struct *channels;
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
//ust//	struct rchan_callbacks callbacks;
	struct kref kref; /* Each channel has a kref of the trace struct */
	struct ltt_transport *transport;
	struct kref ltt_transport_kref;
//ust//	wait_queue_head_t kref_wq; /* Place for ltt_trace_destroy to sleep */
	char trace_name[NAME_MAX];
} ____cacheline_aligned;

/* Hardcoded event headers
 *
 * event header for a trace with active heartbeat : 27 bits timestamps
 *
 * headers are 32-bits aligned. In order to insure such alignment, a dynamic per
 * trace alignment value must be done.
 *
 * Remember that the C compiler does align each member on the boundary
 * equivalent to their own size.
 *
 * As relay subbuffers are aligned on pages, we are sure that they are 4 and 8
 * bytes aligned, so the buffer header and trace header are aligned.
 *
 * Event headers are aligned depending on the trace alignment option.
 *
 * Note using C structure bitfields for cross-endianness and portability
 * concerns.
 */

#define LTT_RESERVED_EVENTS	3
#define LTT_EVENT_BITS		5
#define LTT_FREE_EVENTS		((1 << LTT_EVENT_BITS) - LTT_RESERVED_EVENTS)
#define LTT_TSC_BITS		27
#define LTT_TSC_MASK		((1 << LTT_TSC_BITS) - 1)

struct ltt_event_header {
	u32 id_time;		/* 5 bits event id (MSB); 27 bits time (LSB) */
};

/* Reservation flags */
#define	LTT_RFLAG_ID			(1 << 0)
#define	LTT_RFLAG_ID_SIZE		(1 << 1)
#define	LTT_RFLAG_ID_SIZE_TSC		(1 << 2)

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
	uint32_t lost_size;		/* Size unused at end of subbuffer */
	uint32_t buf_size;		/* Size of this subbuffer */
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
static inline size_t ltt_subbuffer_header_size(void)
{
	return offsetof(struct ltt_subbuffer_header, header_end);
}

/*
 * ltt_get_header_size
 *
 * Calculate alignment offset to 32-bits. This is the alignment offset of the
 * event header.
 *
 * Important note :
 * The event header must be 32-bits. The total offset calculated here :
 *
 * Alignment of header struct on 32 bits (min arch size, header size)
 * + sizeof(header struct)  (32-bits)
 * + (opt) u16 (ext. event id)
 * + (opt) u16 (event_size) (if event_size == 0xFFFFUL, has ext. event size)
 * + (opt) u32 (ext. event size)
 * + (opt) u64 full TSC (aligned on min(64-bits, arch size))
 *
 * The payload must itself determine its own alignment from the biggest type it
 * contains.
 * */
static inline unsigned char ltt_get_header_size(
		struct ltt_channel_struct *channel,
		size_t offset,
		size_t data_size,
		size_t *before_hdr_pad,
		unsigned int rflags)
{
	size_t orig_offset = offset;
	size_t padding;

	BUILD_BUG_ON(sizeof(struct ltt_event_header) != sizeof(u32));

	padding = ltt_align(offset, sizeof(struct ltt_event_header));
	offset += padding;
	offset += sizeof(struct ltt_event_header);

	switch (rflags) {
	case LTT_RFLAG_ID_SIZE_TSC:
		offset += sizeof(u16) + sizeof(u16);
		if (data_size >= 0xFFFFU)
			offset += sizeof(u32);
		offset += ltt_align(offset, sizeof(u64));
		offset += sizeof(u64);
		break;
	case LTT_RFLAG_ID_SIZE:
		offset += sizeof(u16) + sizeof(u16);
		if (data_size >= 0xFFFFU)
			offset += sizeof(u32);
		break;
	case LTT_RFLAG_ID:
		offset += sizeof(u16);
		break;
	}

	*before_hdr_pad = padding;
	return offset - orig_offset;
}

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
static inline size_t ltt_write_event_header(struct ltt_trace_struct *trace,
		struct ltt_channel_struct *channel,
		struct rchan_buf *buf, long buf_offset,
		u16 eID, size_t event_size,
		u64 tsc, unsigned int rflags)
{
	struct ltt_event_header header;
	size_t small_size;

	switch (rflags) {
	case LTT_RFLAG_ID_SIZE_TSC:
		header.id_time = 29 << LTT_TSC_BITS;
		break;
	case LTT_RFLAG_ID_SIZE:
		header.id_time = 30 << LTT_TSC_BITS;
		break;
	case LTT_RFLAG_ID:
		header.id_time = 31 << LTT_TSC_BITS;
		break;
	default:
		header.id_time = eID << LTT_TSC_BITS;
		break;
	}
	header.id_time |= (u32)tsc & LTT_TSC_MASK;
	ltt_relay_write(buf, buf_offset, &header, sizeof(header));
	buf_offset += sizeof(header);

	switch (rflags) {
	case LTT_RFLAG_ID_SIZE_TSC:
		small_size = min_t(size_t, event_size, 0xFFFFU);
		ltt_relay_write(buf, buf_offset,
			(u16[]){ (u16)eID }, sizeof(u16));
		buf_offset += sizeof(u16);
		ltt_relay_write(buf, buf_offset,
			(u16[]){ (u16)small_size }, sizeof(u16));
		buf_offset += sizeof(u16);
		if (small_size == 0xFFFFU) {
			ltt_relay_write(buf, buf_offset,
				(u32[]){ (u32)event_size }, sizeof(u32));
			buf_offset += sizeof(u32);
		}
		buf_offset += ltt_align(buf_offset, sizeof(u64));
		ltt_relay_write(buf, buf_offset,
			(u64[]){ (u64)tsc }, sizeof(u64));
		buf_offset += sizeof(u64);
		break;
	case LTT_RFLAG_ID_SIZE:
		small_size = min_t(size_t, event_size, 0xFFFFU);
		ltt_relay_write(buf, buf_offset,
			(u16[]){ (u16)eID }, sizeof(u16));
		buf_offset += sizeof(u16);
		ltt_relay_write(buf, buf_offset,
			(u16[]){ (u16)small_size }, sizeof(u16));
		buf_offset += sizeof(u16);
		if (small_size == 0xFFFFU) {
			ltt_relay_write(buf, buf_offset,
				(u32[]){ (u32)event_size }, sizeof(u32));
			buf_offset += sizeof(u32);
		}
		break;
	case LTT_RFLAG_ID:
		ltt_relay_write(buf, buf_offset,
			(u16[]){ (u16)eID }, sizeof(u16));
		buf_offset += sizeof(u16);
		break;
	default:
		break;
	}

	return buf_offset;
}

/* Lockless LTTng */

/* Buffer offset macros */

/*
 * BUFFER_TRUNC zeroes the subbuffer offset and the subbuffer number parts of
 * the offset, which leaves only the buffer number.
 */
#define BUFFER_TRUNC(offset, chan) \
	((offset) & (~((chan)->alloc_size-1)))
#define BUFFER_OFFSET(offset, chan) ((offset) & ((chan)->alloc_size - 1))
#define SUBBUF_OFFSET(offset, chan) ((offset) & ((chan)->subbuf_size - 1))
#define SUBBUF_ALIGN(offset, chan) \
	(((offset) + (chan)->subbuf_size) & (~((chan)->subbuf_size - 1)))
#define SUBBUF_TRUNC(offset, chan) \
	((offset) & (~((chan)->subbuf_size - 1)))
#define SUBBUF_INDEX(offset, chan) \
	(BUFFER_OFFSET((offset), chan) >> (chan)->subbuf_size_order)

/*
 * ltt_reserve_slot
 *
 * Atomic slot reservation in a LTTng buffer. It will take care of
 * sub-buffer switching.
 *
 * Parameters:
 *
 * @trace : the trace structure to log to.
 * @channel : the chanel to reserve space into.
 * @transport_data : specific transport data.
 * @data_size : size of the variable length data to log.
 * @slot_size : pointer to total size of the slot (out)
 * @buf_offset : pointer to reserve offset (out)
 * @tsc : pointer to the tsc at the slot reservation (out)
 * @rflags : reservation flags (header specificity)
 * @cpu : cpu id
 *
 * Return : -ENOSPC if not enough space, else 0.
 */
static inline int ltt_reserve_slot(
		struct ltt_trace_struct *trace,
		struct ltt_channel_struct *channel,
		void **transport_data,
		size_t data_size,
		size_t *slot_size,
		long *buf_offset,
		u64 *tsc,
		unsigned int *rflags,
		int largest_align,
		int cpu)
{
	return trace->ops->reserve_slot(trace, channel, transport_data,
			data_size, slot_size, buf_offset, tsc, rflags,
			largest_align, cpu);
}


/*
 * ltt_commit_slot
 *
 * Atomic unordered slot commit. Increments the commit count in the
 * specified sub-buffer, and delivers it if necessary.
 *
 * Parameters:
 *
 * @channel : the chanel to reserve space into.
 * @transport_data : specific transport data.
 * @buf_offset : offset of beginning of reserved slot
 * @slot_size : size of the reserved slot.
 */
static inline void ltt_commit_slot(
		struct ltt_channel_struct *channel,
		void **transport_data,
		long buf_offset,
		size_t slot_size)
{
	struct ltt_trace_struct *trace = channel->trace;

	trace->ops->commit_slot(channel, transport_data, buf_offset, slot_size);
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
//ust// #define LTT_RELAY_ROOT		"ltt"
//ust// #define LTT_RELAY_LOCKED_ROOT	"ltt-locked"

#define LTT_METADATA_CHANNEL		"metadata_state"
#define LTT_UST_CHANNEL			"ust"

#define LTT_FLIGHT_PREFIX	"flight-"

/* Tracer properties */
#define LTT_DEFAULT_SUBBUF_SIZE_LOW	65536
#define LTT_DEFAULT_N_SUBBUFS_LOW	2
#define LTT_DEFAULT_SUBBUF_SIZE_MED	262144
#define LTT_DEFAULT_N_SUBBUFS_MED	2
#define LTT_DEFAULT_SUBBUF_SIZE_HIGH	1048576
#define LTT_DEFAULT_N_SUBBUFS_HIGH	2
#define LTT_TRACER_MAGIC_NUMBER		0x00D6B7ED
#define LTT_TRACER_VERSION_MAJOR	2
#define LTT_TRACER_VERSION_MINOR	3

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

//ust// extern int ltt_module_register(enum ltt_module_function name, void *function,
//ust// 		struct module *owner);
//ust// extern void ltt_module_unregister(enum ltt_module_function name);

void ltt_transport_register(struct ltt_transport *transport);
void ltt_transport_unregister(struct ltt_transport *transport);

/* Exported control function */

//ust// enum ltt_control_msg {
//ust// 	LTT_CONTROL_START,
//ust// 	LTT_CONTROL_STOP,
//ust// 	LTT_CONTROL_CREATE_TRACE,
//ust// 	LTT_CONTROL_DESTROY_TRACE
//ust// };

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

int _ltt_trace_setup(const char *trace_name);
int ltt_trace_setup(const char *trace_name);
struct ltt_trace_struct *_ltt_trace_find_setup(const char *trace_name);
int ltt_trace_set_type(const char *trace_name, const char *trace_type);
int ltt_trace_set_channel_subbufsize(const char *trace_name,
		const char *channel_name, unsigned int size);
int ltt_trace_set_channel_subbufcount(const char *trace_name,
		const char *channel_name, unsigned int cnt);
int ltt_trace_set_channel_enable(const char *trace_name,
		const char *channel_name, unsigned int enable);
int ltt_trace_set_channel_overwrite(const char *trace_name,
		const char *channel_name, unsigned int overwrite);
int ltt_trace_alloc(const char *trace_name);
int ltt_trace_destroy(const char *trace_name);
int ltt_trace_start(const char *trace_name);
int ltt_trace_stop(const char *trace_name);

//ust// extern int ltt_control(enum ltt_control_msg msg, const char *trace_name,
//ust// 		const char *trace_type, union ltt_control_args args);

enum ltt_filter_control_msg {
	LTT_FILTER_DEFAULT_ACCEPT,
	LTT_FILTER_DEFAULT_REJECT
};

extern int ltt_filter_control(enum ltt_filter_control_msg msg,
		const char *trace_name);

extern struct dentry *get_filter_root(void);

void ltt_write_trace_header(struct ltt_trace_struct *trace,
		struct ltt_subbuffer_header *header);
extern void ltt_buffer_destroy(struct ltt_channel_struct *ltt_chan);

void ltt_core_register(int (*function)(u8, void *));

void ltt_core_unregister(void);

void ltt_release_trace(struct kref *kref);
void ltt_release_transport(struct kref *kref);

extern int ltt_probe_register(struct ltt_available_probe *pdata);
extern int ltt_probe_unregister(struct ltt_available_probe *pdata);
extern int ltt_marker_connect(const char *channel, const char *mname,
		const char *pname);
extern int ltt_marker_disconnect(const char *channel, const char *mname,
		const char *pname);
extern void ltt_dump_marker_state(struct ltt_trace_struct *trace);

void ltt_lock_traces(void);
void ltt_unlock_traces(void);

//ust// extern void ltt_dump_softirq_vec(void *call_data);
//ust// 
//ust// #ifdef CONFIG_HAVE_LTT_DUMP_TABLES
//ust// extern void ltt_dump_sys_call_table(void *call_data);
//ust// extern void ltt_dump_idt_table(void *call_data);
//ust// #else
//ust// static inline void ltt_dump_sys_call_table(void *call_data)
//ust// {
//ust// }
//ust// 
//ust// static inline void ltt_dump_idt_table(void *call_data)
//ust// {
//ust// }
//ust// #endif

//ust// #ifdef CONFIG_LTT_KPROBES
//ust// extern void ltt_dump_kprobes_table(void *call_data);
//ust// #else
//ust// static inline void ltt_dump_kprobes_table(void *call_data)
//ust// {
//ust// }
//ust// #endif

//ust// /* Relay IOCTL */
//ust// 
//ust// /* Get the next sub buffer that can be read. */
//ust// #define RELAY_GET_SUBBUF		_IOR(0xF5, 0x00, __u32)
//ust// /* Release the oldest reserved (by "get") sub buffer. */
//ust// #define RELAY_PUT_SUBBUF		_IOW(0xF5, 0x01, __u32)
//ust// /* returns the number of sub buffers in the per cpu channel. */
//ust// #define RELAY_GET_N_SUBBUFS		_IOR(0xF5, 0x02, __u32)
//ust// /* returns the size of the sub buffers. */
//ust// #define RELAY_GET_SUBBUF_SIZE		_IOR(0xF5, 0x03, __u32)

//ust// #endif /* CONFIG_LTT */

#endif /* _LTT_TRACER_H */
