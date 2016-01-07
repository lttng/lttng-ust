/*
 * Copyright (C) 2016 - EfficiOS Inc., Alexandre Montplaisir <alexmonthy@efficios.com>
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

#ifndef LIBLTTNG_UST_JAVA_AGENT_JNI_COMMON_LTTNG_UST_CONTEXT_H_
#define LIBLTTNG_UST_JAVA_AGENT_JNI_COMMON_LTTNG_UST_CONTEXT_H_

struct lttng_ust_jni_ctx;

struct lttng_ust_jni_tls {
	struct lttng_ust_jni_ctx *ctx;
	int32_t len;
};

extern __thread struct lttng_ust_jni_tls lttng_ust_context_info_tls;

#endif /* LIBLTTNG_UST_JAVA_AGENT_JNI_COMMON_LTTNG_UST_CONTEXT_H_ */
