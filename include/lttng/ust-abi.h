// SPDX-FileCopyrightText: 2010-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
//
// SPDX-License-Identifier: MIT

/*
 * LTTng-UST ABI header
 */

#ifndef _LTTNG_UST_ABI_H
#define _LTTNG_UST_ABI_H

#include <stdint.h>
#include <lttng/ust-compiler.h>

#define LTTNG_UST_ABI_SYM_NAME_LEN			256
#define LTTNG_UST_ABI_PROCNAME_LEN		16

/* UST comm magic number, used to validate protocol and endianness. */
#define LTTNG_UST_ABI_COMM_MAGIC			0xC57C57C5

/* Version for ABI between liblttng-ust, sessiond, consumerd */
#define LTTNG_UST_ABI_MAJOR_VERSION			10
#define LTTNG_UST_ABI_MAJOR_VERSION_OLDEST_COMPATIBLE	8
#define LTTNG_UST_ABI_MINOR_VERSION		0

#define LTTNG_UST_ABI_CMD_MAX_LEN			4096U

enum lttng_ust_abi_instrumentation {
	LTTNG_UST_ABI_TRACEPOINT	= 0,
	LTTNG_UST_ABI_PROBE		= 1,
	LTTNG_UST_ABI_FUNCTION		= 2,
};

enum lttng_ust_abi_loglevel_type {
	LTTNG_UST_ABI_LOGLEVEL_ALL	= 0,
	LTTNG_UST_ABI_LOGLEVEL_RANGE	= 1,
	LTTNG_UST_ABI_LOGLEVEL_SINGLE	= 2,
};

enum lttng_ust_abi_output {
	LTTNG_UST_ABI_MMAP		= 0,
};

enum lttng_ust_abi_chan_type {
	LTTNG_UST_ABI_CHAN_PER_CPU	= 0,
	LTTNG_UST_ABI_CHAN_METADATA	= 1,
	LTTNG_UST_ABI_CHAN_PER_CHANNEL	= 2,
};

struct lttng_ust_abi_tracer_version {
	uint32_t major;
	uint32_t minor;
	uint32_t patchlevel;
} __attribute__((packed));

#define LTTNG_UST_ABI_CHANNEL_PADDING	(LTTNG_UST_ABI_SYM_NAME_LEN + 32)
/*
 * Given that the consumerd is limited to 64k file descriptors, we
 * cannot expect much more than 1MB channel structure size. This size is
 * depends on the number of streams within a channel, which depends on
 * the number of possible CPUs on the system.
 */
#define LTTNG_UST_ABI_CHANNEL_DATA_MAX_LEN	1048576U
struct lttng_ust_abi_channel {
	uint64_t len;
	int32_t type;	/* enum lttng_ust_abi_chan_type */
	char padding[LTTNG_UST_ABI_CHANNEL_PADDING];
	char data[];	/* variable sized data */
} __attribute__((packed));

#define LTTNG_UST_ABI_STREAM_PADDING1	(LTTNG_UST_ABI_SYM_NAME_LEN + 32)
struct lttng_ust_abi_stream {
	uint64_t len;		/* shm len */
	uint32_t stream_nr;	/* stream number */
	char padding[LTTNG_UST_ABI_STREAM_PADDING1];
	/*
	 * shm_fd and wakeup_fd are send over unix socket as file
	 * descriptors after this structure.
	 */
} __attribute__((packed));

#define LTTNG_UST_ABI_EVENT_PADDING1	8
#define LTTNG_UST_ABI_EVENT_PADDING2	(LTTNG_UST_ABI_SYM_NAME_LEN + 32)
struct lttng_ust_abi_event {
	int32_t instrumentation; 		/* enum lttng_ust_abi_instrumentation */
	char name[LTTNG_UST_ABI_SYM_NAME_LEN];	/* event name */

	int32_t loglevel_type;			/* enum lttng_ust_abi_loglevel_type */
	int32_t loglevel;			/* value, -1: all */
	uint64_t token;				/* User-provided token */
	char padding[LTTNG_UST_ABI_EVENT_PADDING1];

	/* Per instrumentation type configuration */
	union {
		char padding[LTTNG_UST_ABI_EVENT_PADDING2];
	} u;
} __attribute__((packed));

#define LTTNG_UST_ABI_EVENT_NOTIFIER_PADDING	32
struct lttng_ust_abi_event_notifier {
	struct lttng_ust_abi_event event;
	uint64_t error_counter_index;
	char padding[LTTNG_UST_ABI_EVENT_NOTIFIER_PADDING];
} __attribute__((packed));

#define LTTNG_UST_ABI_EVENT_NOTIFIER_NOTIFICATION_PADDING 32
struct lttng_ust_abi_event_notifier_notification {
	uint64_t token;
	uint16_t capture_buf_size;
	char padding[LTTNG_UST_ABI_EVENT_NOTIFIER_NOTIFICATION_PADDING];
} __attribute__((packed));

enum lttng_ust_abi_key_token_type {
	LTTNG_UST_ABI_KEY_TOKEN_STRING = 0,		/* arg: strtab_offset. */
	LTTNG_UST_ABI_KEY_TOKEN_EVENT_NAME = 1,		/* no arg. */
	LTTNG_UST_ABI_KEY_TOKEN_PROVIDER_NAME = 2,	/* no arg. */
};

enum lttng_ust_abi_counter_arithmetic {
	LTTNG_UST_ABI_COUNTER_ARITHMETIC_MODULAR = 0,
	LTTNG_UST_ABI_COUNTER_ARITHMETIC_SATURATION = 1,
};

enum lttng_ust_abi_counter_bitness {
	LTTNG_UST_ABI_COUNTER_BITNESS_32 = 0,
	LTTNG_UST_ABI_COUNTER_BITNESS_64 = 1,
};

#ifdef CONFIG_LTTNG_UST_EXPERIMENTAL_COUNTER
struct lttng_ust_abi_key_token {
	uint32_t len;				/* length of child structure. */
	uint32_t type;				/* enum lttng_ust_abi_key_token_type */
	/*
	 * The size of this structure is fixed because it is embedded into
	 * children structures.
	 */
} __attribute__((packed));

/* Length of this structure excludes the following string. */
struct lttng_ust_abi_key_token_string {
	struct lttng_ust_abi_key_token parent;
	uint32_t string_len;		/* string length (includes \0) */

	char str[];			/* Null-terminated string following this structure. */
} __attribute__((packed));
#endif	 /* CONFIG_LTTNG_UST_EXPERIMENTAL_COUNTER */

/*
 * token types event_name and provider_name don't have specific fields,
 * so they do not need to derive their own specific child structure.
 */

/*
 * Dimension indexing: All events should use the same key type to index
 * a given map dimension.
 */
enum lttng_ust_abi_key_type {
	LTTNG_UST_ABI_KEY_TYPE_TOKENS = 0,		/* Dimension key is a set of tokens. */
	LTTNG_UST_ABI_KEY_TYPE_INTEGER = 1,		/* Dimension key is an integer value. */
};

#ifdef CONFIG_LTTNG_UST_EXPERIMENTAL_COUNTER
struct lttng_ust_abi_counter_key_dimension {
	uint32_t len;				/* length of child structure */
	uint32_t key_type;			/* enum lttng_ust_abi_key_type */
	/*
	 * The size of this structure is fixed because it is embedded into
	 * children structures.
	 */
} __attribute__((packed));

struct lttng_ust_abi_counter_key_dimension_tokens {
	struct lttng_ust_abi_counter_key_dimension parent;
	uint32_t nr_key_tokens;

	/* Followed by an array of nr_key_tokens struct lttng_ust_abi_key_token elements. */
} __attribute__((packed));

/*
 * The "integer" key type is not implemented yet, but when it will be
 * introduced in the future, its specific key dimension will allow
 * defining the function to apply over input argument, bytecode to run
 * and so on.
 */

enum lttng_ust_abi_counter_action {
	LTTNG_UST_ABI_COUNTER_ACTION_INCREMENT = 0,

	/*
	 * Can be extended with additional actions, such as decrement,
	 * set value, run bytecode, and so on.
	 */
};

struct lttng_ust_abi_counter_event {
	uint32_t len;				/* length of this structure */
	uint32_t action;			/* enum lttng_ust_abi_counter_action */

	struct lttng_ust_abi_event event;
	uint32_t number_key_dimensions;		/* array of dimensions is an array of var. len. elements. */

	/*
	 * Followed by additional data specific to the action, and by a
	 * variable-length array of key dimensions.
	 */
} __attribute__((packed));
#endif	/* CONFIG_LTTNG_UST_EXPERIMENTAL_COUNTER */

enum lttng_ust_abi_counter_dimension_flags {
	LTTNG_UST_ABI_COUNTER_DIMENSION_FLAG_UNDERFLOW = (1 << 0),
	LTTNG_UST_ABI_COUNTER_DIMENSION_FLAG_OVERFLOW = (1 << 1),
};

struct lttng_ust_abi_counter_dimension {
	uint32_t key_type;			/* enum lttng_ust_abi_key_type */
	uint32_t flags;				/* enum lttng_ust_abi_counter_dimension_flags */
	uint64_t size;				/* dimension size (count of entries) */
	uint64_t underflow_index;
	uint64_t overflow_index;
} __attribute__((packed));

enum lttng_ust_abi_counter_conf_flags {
	LTTNG_UST_ABI_COUNTER_CONF_FLAG_COALESCE_HITS = (1 << 0),
};

struct lttng_ust_abi_counter_conf {
	uint32_t len;				/* Length of fields before var. len. data. */
	uint32_t flags;				/* enum lttng_ust_abi_counter_conf_flags */
	uint32_t arithmetic;			/* enum lttng_ust_abi_counter_arithmetic */
	uint32_t bitness;			/* enum lttng_ust_abi_counter_bitness */
	int64_t global_sum_step;
	uint32_t number_dimensions;
	uint32_t elem_len;			/* array stride (size of lttng_ust_abi_counter_dimension) */
} __attribute__((packed));

struct lttng_ust_abi_counter_channel {
	uint32_t len;				/* Length of this structure */
	uint64_t shm_len;			/* shm len */
} __attribute__((packed));

struct lttng_ust_abi_counter_cpu {
	uint32_t len;				/* Length of this structure */
	uint64_t shm_len;			/* shm len */
	uint32_t cpu_nr;
} __attribute__((packed));

enum lttng_ust_abi_field_type {
	LTTNG_UST_ABI_FIELD_OTHER			= 0,
	LTTNG_UST_ABI_FIELD_INTEGER			= 1,
	LTTNG_UST_ABI_FIELD_ENUM			= 2,
	LTTNG_UST_ABI_FIELD_FLOAT			= 3,
	LTTNG_UST_ABI_FIELD_STRING			= 4,
};

#define LTTNG_UST_ABI_FIELD_ITER_PADDING	(LTTNG_UST_ABI_SYM_NAME_LEN + 28)
struct lttng_ust_abi_field_iter {
	char event_name[LTTNG_UST_ABI_SYM_NAME_LEN];
	char field_name[LTTNG_UST_ABI_SYM_NAME_LEN];
	int32_t type;				/* enum lttng_ust_abi_field_type */
	int loglevel;				/* event loglevel */
	int nowrite;
	char padding[LTTNG_UST_ABI_FIELD_ITER_PADDING];
} __attribute__((packed));

enum lttng_ust_abi_context_type {
	LTTNG_UST_ABI_CONTEXT_VTID			= 0,
	LTTNG_UST_ABI_CONTEXT_VPID			= 1,
	LTTNG_UST_ABI_CONTEXT_PTHREAD_ID		= 2,
	LTTNG_UST_ABI_CONTEXT_PROCNAME			= 3,
	LTTNG_UST_ABI_CONTEXT_IP			= 4,
	LTTNG_UST_ABI_CONTEXT_PERF_THREAD_COUNTER	= 5,
	LTTNG_UST_ABI_CONTEXT_CPU_ID			= 6,
	LTTNG_UST_ABI_CONTEXT_APP_CONTEXT		= 7,
	LTTNG_UST_ABI_CONTEXT_CGROUP_NS			= 8,
	LTTNG_UST_ABI_CONTEXT_IPC_NS			= 9,
	LTTNG_UST_ABI_CONTEXT_MNT_NS			= 10,
	LTTNG_UST_ABI_CONTEXT_NET_NS			= 11,
	LTTNG_UST_ABI_CONTEXT_PID_NS			= 12,
	LTTNG_UST_ABI_CONTEXT_USER_NS			= 13,
	LTTNG_UST_ABI_CONTEXT_UTS_NS			= 14,
	LTTNG_UST_ABI_CONTEXT_VUID			= 15,
	LTTNG_UST_ABI_CONTEXT_VEUID			= 16,
	LTTNG_UST_ABI_CONTEXT_VSUID			= 17,
	LTTNG_UST_ABI_CONTEXT_VGID			= 18,
	LTTNG_UST_ABI_CONTEXT_VEGID			= 19,
	LTTNG_UST_ABI_CONTEXT_VSGID			= 20,
	LTTNG_UST_ABI_CONTEXT_TIME_NS			= 21,
};

struct lttng_ust_abi_perf_counter_ctx {
	uint32_t type;
	uint64_t config;
	char name[LTTNG_UST_ABI_SYM_NAME_LEN];
} __attribute__((packed));

#define LTTNG_UST_ABI_CONTEXT_PADDING1	16
#define LTTNG_UST_ABI_CONTEXT_PADDING2	(LTTNG_UST_ABI_SYM_NAME_LEN + 32)
struct lttng_ust_abi_context {
	int32_t ctx;	 /* enum lttng_ust_abi_context_type */
	char padding[LTTNG_UST_ABI_CONTEXT_PADDING1];

	union {
		struct lttng_ust_abi_perf_counter_ctx perf_counter;
		struct {
			/* Includes trailing '\0'. */
			uint32_t provider_name_len;
			uint32_t ctx_name_len;
		} app_ctx;
		char padding[LTTNG_UST_ABI_CONTEXT_PADDING2];
	} u;
} __attribute__((packed));

/*
 * Tracer channel attributes.
 */
#define LTTNG_UST_ABI_CHANNEL_ATTR_PADDING	(LTTNG_UST_ABI_SYM_NAME_LEN + 32)
struct lttng_ust_abi_channel_attr {
	uint64_t subbuf_size;			/* bytes */
	uint64_t num_subbuf;			/* power of 2 */
	int overwrite;				/* 1: overwrite, 0: discard */
	unsigned int switch_timer_interval;	/* usec */
	unsigned int read_timer_interval;	/* usec */
	int32_t output;				/* enum lttng_ust_abi_output */
	union {
		struct {
			int64_t blocking_timeout;	/* Blocking timeout (usec) */
			int8_t type;			/* enum lttng_ust_abi_chan_type */
		} s;
		char padding[LTTNG_UST_ABI_CHANNEL_ATTR_PADDING];
	} u;
} __attribute__((packed));

#define LTTNG_UST_ABI_TRACEPOINT_ITER_PADDING	16
struct lttng_ust_abi_tracepoint_iter {
	char name[LTTNG_UST_ABI_SYM_NAME_LEN];	/* provider:name */
	int loglevel;
	char padding[LTTNG_UST_ABI_TRACEPOINT_ITER_PADDING];
} __attribute__((packed));

enum lttng_ust_abi_object_type {
	LTTNG_UST_ABI_OBJECT_TYPE_UNKNOWN = -1,
	LTTNG_UST_ABI_OBJECT_TYPE_CHANNEL = 0,
	LTTNG_UST_ABI_OBJECT_TYPE_STREAM = 1,
	LTTNG_UST_ABI_OBJECT_TYPE_EVENT = 2,
	LTTNG_UST_ABI_OBJECT_TYPE_CONTEXT = 3,
	LTTNG_UST_ABI_OBJECT_TYPE_EVENT_NOTIFIER_GROUP = 4,
	LTTNG_UST_ABI_OBJECT_TYPE_EVENT_NOTIFIER = 5,
	LTTNG_UST_ABI_OBJECT_TYPE_COUNTER = 6,
	LTTNG_UST_ABI_OBJECT_TYPE_COUNTER_CHANNEL = 7,
	LTTNG_UST_ABI_OBJECT_TYPE_COUNTER_CPU = 8,
	LTTNG_UST_ABI_OBJECT_TYPE_COUNTER_EVENT = 9,
};

#define LTTNG_UST_ABI_OBJECT_DATA_PADDING1	32
#define LTTNG_UST_ABI_OBJECT_DATA_PADDING2	(LTTNG_UST_ABI_SYM_NAME_LEN + 32)

struct lttng_ust_abi_object_data {
	int32_t type;	/* enum lttng_ust_abi_object_type */
	int handle;
	uint64_t size;
	char padding1[LTTNG_UST_ABI_OBJECT_DATA_PADDING1];
	union {
		struct {
			void *data;
			int32_t type;	/* enum lttng_ust_abi_chan_type */
			int wakeup_fd;
		} channel;
		struct {
			int shm_fd;
			int wakeup_fd;
			uint32_t stream_nr;
		} stream;
		struct {
			void *data;
		} counter;
		struct {
			int shm_fd;
		} counter_channel;
		struct {
			int shm_fd;
			uint32_t cpu_nr;
		} counter_cpu;
		char padding2[LTTNG_UST_ABI_OBJECT_DATA_PADDING2];
	} u;
} __attribute__((packed));

enum lttng_ust_abi_calibrate_type {
	LTTNG_UST_ABI_CALIBRATE_TRACEPOINT,
};

#define LTTNG_UST_ABI_CALIBRATE_PADDING1	16
#define LTTNG_UST_ABI_CALIBRATE_PADDING2	(LTTNG_UST_ABI_SYM_NAME_LEN + 32)
struct lttng_ust_abi_calibrate {
	enum lttng_ust_abi_calibrate_type type;		/* type (input) */
	char padding[LTTNG_UST_ABI_CALIBRATE_PADDING1];

	union {
		char padding[LTTNG_UST_ABI_CALIBRATE_PADDING2];
	} u;
} __attribute__((packed));

#define LTTNG_UST_ABI_FILTER_BYTECODE_MAX_LEN	65536
#define LTTNG_UST_ABI_FILTER_PADDING		32
struct lttng_ust_abi_filter_bytecode {
	uint32_t len;
	uint32_t reloc_offset;
	uint64_t seqnum;
	char padding[LTTNG_UST_ABI_FILTER_PADDING];
	char data[0];
} __attribute__((packed));

#define LTTNG_UST_ABI_CAPTURE_BYTECODE_MAX_LEN	65536
#define LTTNG_UST_ABI_CAPTURE_PADDING		32
struct lttng_ust_abi_capture_bytecode {
	uint32_t len;
	uint32_t reloc_offset;
	uint64_t seqnum;
	char padding[LTTNG_UST_ABI_CAPTURE_PADDING];
	char data[0];
} __attribute__((packed));

#define LTTNG_UST_ABI_EXCLUSION_PADDING	32
struct lttng_ust_abi_event_exclusion {
	uint32_t count;
	char padding[LTTNG_UST_ABI_EXCLUSION_PADDING];
	char names[LTTNG_UST_ABI_SYM_NAME_LEN][0];
} __attribute__((packed));

#define LTTNG_UST_ABI_CMD(minor)			(minor)
#define LTTNG_UST_ABI_CMDR(minor, type)			(minor)
#define LTTNG_UST_ABI_CMDW(minor, type)			(minor)
#define LTTNG_UST_ABI_CMDV(minor, var_len_cmd_type)	(minor)

/* Handled by object descriptor */
#define LTTNG_UST_ABI_RELEASE			LTTNG_UST_ABI_CMD(0x1)

/* Handled by object cmd */

/* LTTng-UST commands */
#define LTTNG_UST_ABI_SESSION			LTTNG_UST_ABI_CMD(0x40)
#define LTTNG_UST_ABI_TRACER_VERSION		\
	LTTNG_UST_ABI_CMDR(0x41, struct lttng_ust_abi_tracer_version)
#define LTTNG_UST_ABI_TRACEPOINT_LIST		LTTNG_UST_ABI_CMD(0x42)
#define LTTNG_UST_ABI_WAIT_QUIESCENT		LTTNG_UST_ABI_CMD(0x43)
#define LTTNG_UST_ABI_REGISTER_DONE		LTTNG_UST_ABI_CMD(0x44)
#define LTTNG_UST_ABI_TRACEPOINT_FIELD_LIST	LTTNG_UST_ABI_CMD(0x45)
#define LTTNG_UST_ABI_EVENT_NOTIFIER_GROUP_CREATE \
	LTTNG_UST_ABI_CMD(0x46)

/* Session commands */
#define LTTNG_UST_ABI_CHANNEL			\
	LTTNG_UST_ABI_CMDW(0x51, struct lttng_ust_abi_channel)
#define LTTNG_UST_ABI_SESSION_START		LTTNG_UST_ABI_CMD(0x52)
#define LTTNG_UST_ABI_SESSION_STOP		LTTNG_UST_ABI_CMD(0x53)
#define LTTNG_UST_ABI_SESSION_STATEDUMP		LTTNG_UST_ABI_CMD(0x54)

/* Channel commands */
#define LTTNG_UST_ABI_STREAM			LTTNG_UST_ABI_CMD(0x60)
#define LTTNG_UST_ABI_EVENT			\
	LTTNG_UST_ABI_CMDW(0x61, struct lttng_ust_abi_event)

/* Event and channel commands */
#define LTTNG_UST_ABI_CONTEXT			\
	LTTNG_UST_ABI_CMDW(0x70, struct lttng_ust_abi_context)
#define LTTNG_UST_ABI_FLUSH_BUFFER		\
	LTTNG_UST_ABI_CMD(0x71)

/* Event, event notifier, channel and session commands */
#define LTTNG_UST_ABI_ENABLE			LTTNG_UST_ABI_CMD(0x80)
#define LTTNG_UST_ABI_DISABLE			LTTNG_UST_ABI_CMD(0x81)

/* Tracepoint list commands */
#define LTTNG_UST_ABI_TRACEPOINT_LIST_GET	LTTNG_UST_ABI_CMD(0x90)
#define LTTNG_UST_ABI_TRACEPOINT_FIELD_LIST_GET	LTTNG_UST_ABI_CMD(0x91)

/* Event and event notifier commands */
#define LTTNG_UST_ABI_FILTER			LTTNG_UST_ABI_CMD(0xA0)
#define LTTNG_UST_ABI_EXCLUSION			LTTNG_UST_ABI_CMD(0xA1)

/* Event notifier group commands */
#define LTTNG_UST_ABI_EVENT_NOTIFIER_CREATE	\
	LTTNG_UST_ABI_CMDV(0xB0, struct lttng_ust_abi_event_notifier)

/* Event notifier commands */
#define LTTNG_UST_ABI_CAPTURE			LTTNG_UST_ABI_CMD(0xB6)

/* Session and event notifier group commands */
/* (0xC0) reserved for old ABI. */
#define LTTNG_UST_ABI_COUNTER			\
	LTTNG_UST_ABI_CMDV(0xC1, struct lttng_ust_abi_counter_conf)

/* Counter commands */
/* (0xD0, 0xD1) reserved for old ABI. */
#define LTTNG_UST_ABI_COUNTER_CHANNEL		\
	LTTNG_UST_ABI_CMDV(0xD2, struct lttng_ust_abi_counter_channel)
#define LTTNG_UST_ABI_COUNTER_CPU		\
	LTTNG_UST_ABI_CMDV(0xD3, struct lttng_ust_abi_counter_cpu)
#define LTTNG_UST_ABI_COUNTER_EVENT		\
	LTTNG_UST_ABI_CMDV(0xD4, struct lttng_ust_abi_counter_event)

#define LTTNG_UST_ABI_ROOT_HANDLE	0

#endif /* _LTTNG_UST_ABI_H */
