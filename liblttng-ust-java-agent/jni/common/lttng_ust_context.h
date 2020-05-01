/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2016 EfficiOS Inc.
 * Copyright (C) 2016 Alexandre Montplaisir <alexmonthy@efficios.com>
 */

#ifndef LIBLTTNG_UST_JAVA_AGENT_JNI_COMMON_LTTNG_UST_CONTEXT_H_
#define LIBLTTNG_UST_JAVA_AGENT_JNI_COMMON_LTTNG_UST_CONTEXT_H_

struct lttng_ust_jni_ctx_entry;

struct lttng_ust_jni_tls {
	struct lttng_ust_jni_ctx_entry *ctx_entries;
	int32_t ctx_entries_len;
	signed char *ctx_strings;
	int32_t ctx_strings_len;
};

extern __thread struct lttng_ust_jni_tls lttng_ust_context_info_tls;

#endif /* LIBLTTNG_UST_JAVA_AGENT_JNI_COMMON_LTTNG_UST_CONTEXT_H_ */
