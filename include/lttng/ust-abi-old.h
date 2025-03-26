/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2010-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng-UST ABI header
 */

#ifndef _LTTNG_UST_ABI_OLD_H
#define _LTTNG_UST_ABI_OLD_H

#include <stdint.h>
#include <lttng/ust-abi.h>

#define LTTNG_UST_ABI_OLD_SYM_NAME_LEN			256
#define LTTNG_UST_ABI_OLD_COUNTER_DIMENSION_MAX		4

struct lttng_ust_abi_old_counter_dimension {
	uint64_t size;
	uint64_t underflow_index;
	uint64_t overflow_index;
	uint8_t has_underflow;
	uint8_t has_overflow;
} __attribute__((packed));

#define LTTNG_UST_ABI_OLD_COUNTER_CONF_PADDING1		67
struct lttng_ust_abi_old_counter_conf {
	uint32_t arithmetic;	/* enum lttng_ust_abi_counter_arithmetic */
	uint32_t bitness;	/* enum lttng_ust_abi_counter_bitness */
	uint32_t number_dimensions;
	int64_t global_sum_step;
	struct lttng_ust_abi_old_counter_dimension dimensions[LTTNG_UST_ABI_OLD_COUNTER_DIMENSION_MAX];
	uint8_t coalesce_hits;
	char padding[LTTNG_UST_ABI_OLD_COUNTER_CONF_PADDING1];
} __attribute__((packed));

#define LTTNG_UST_ABI_OLD_COUNTER_PADDING1		(LTTNG_UST_ABI_OLD_SYM_NAME_LEN + 32)
#define LTTNG_UST_ABI_OLD_COUNTER_DATA_MAX_LEN		4096U
struct lttng_ust_abi_old_counter {
	uint64_t len;
	char padding[LTTNG_UST_ABI_OLD_COUNTER_PADDING1];
	char data[];    /* variable sized data */
} __attribute__((packed));

#define LTTNG_UST_ABI_OLD_COUNTER_CHANNEL_PADDING1	(LTTNG_UST_ABI_OLD_SYM_NAME_LEN + 32)
struct lttng_ust_abi_old_counter_channel {
	uint64_t len;	/* shm len */
	char padding[LTTNG_UST_ABI_OLD_COUNTER_CHANNEL_PADDING1];
} __attribute__((packed));

#define LTTNG_UST_ABI_OLD_COUNTER_CPU_PADDING1		(LTTNG_UST_ABI_OLD_SYM_NAME_LEN + 32)
struct lttng_ust_abi_old_counter_cpu {
	uint64_t len;	/* shm len */
	uint32_t cpu_nr;
	char padding[LTTNG_UST_ABI_OLD_COUNTER_CPU_PADDING1];
} __attribute__((packed));

/* Event notifier group commands */
#define LTTNG_UST_ABI_OLD_COUNTER		\
	LTTNG_UST_ABI_CMDW(0xC0, struct lttng_ust_abi_old_counter)

/* Counter commands */
#define LTTNG_UST_ABI_OLD_COUNTER_CHANNEL	\
	LTTNG_UST_ABI_CMDW(0xD0, struct lttng_ust_abi_old_counter_channel)
#define LTTNG_UST_ABI_OLD_COUNTER_CPU		\
	LTTNG_UST_ABI_CMDW(0xD1, struct lttng_ust_abi_old_counter_cpu)

#endif /* _LTTNG_UST_ABI_OLD_H */
