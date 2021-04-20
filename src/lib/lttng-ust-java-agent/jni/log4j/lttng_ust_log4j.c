/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2016 EfficiOS Inc.
 * Copyright (C) 2016 Alexandre Montplaisir <alexmonthy@efficios.com>
 * Copyright (C) 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#define _LGPL_SOURCE
#include "org_lttng_ust_agent_log4j_LttngLog4jApi.h"

#define LTTNG_UST_TRACEPOINT_DEFINE
#define LTTNG_UST_TRACEPOINT_CREATE_PROBES
#include "lttng_ust_log4j.h"
#include "../common/lttng_ust_context.h"

/*
 * Deprecated function from before the context information was passed.
 */
JNIEXPORT void JNICALL Java_org_lttng_ust_agent_log4j_LttngLog4jApi_tracepoint(JNIEnv *env,
						jobject jobj __attribute__((unused)),
						jstring msg,
						jstring logger_name,
						jstring class_name,
						jstring method_name,
						jstring file_name,
						jint line_number,
						jlong timestamp,
						jint loglevel,
						jstring thread_name)
{
	jboolean iscopy;
	const char *msg_cstr = (*env)->GetStringUTFChars(env, msg, &iscopy);
	const char *logger_name_cstr = (*env)->GetStringUTFChars(env, logger_name, &iscopy);
	const char *class_name_cstr = (*env)->GetStringUTFChars(env, class_name, &iscopy);
	const char *method_name_cstr = (*env)->GetStringUTFChars(env, method_name, &iscopy);
	const char *file_name_cstr = (*env)->GetStringUTFChars(env, file_name, &iscopy);
	const char *thread_name_cstr = (*env)->GetStringUTFChars(env, thread_name, &iscopy);

	lttng_ust_tracepoint(lttng_log4j, event, msg_cstr, logger_name_cstr,
		   class_name_cstr, method_name_cstr, file_name_cstr,
		   line_number, timestamp, loglevel, thread_name_cstr);

	(*env)->ReleaseStringUTFChars(env, msg, msg_cstr);
	(*env)->ReleaseStringUTFChars(env, logger_name, logger_name_cstr);
	(*env)->ReleaseStringUTFChars(env, class_name, class_name_cstr);
	(*env)->ReleaseStringUTFChars(env, method_name, method_name_cstr);
	(*env)->ReleaseStringUTFChars(env, file_name, file_name_cstr);
	(*env)->ReleaseStringUTFChars(env, thread_name, thread_name_cstr);
}

/*
 * Tracepoint used by Java applications using the log4j handler.
 */
JNIEXPORT void JNICALL Java_org_lttng_ust_agent_log4j_LttngLog4jApi_tracepointWithContext(JNIEnv *env,
						jobject jobj __attribute__((unused)),
						jstring msg,
						jstring logger_name,
						jstring class_name,
						jstring method_name,
						jstring file_name,
						jint line_number,
						jlong timestamp,
						jint loglevel,
						jstring thread_name,
						jbyteArray context_info_entries,
						jbyteArray context_info_strings)
{
	jboolean iscopy;
	const char *msg_cstr = (*env)->GetStringUTFChars(env, msg, &iscopy);
	const char *logger_name_cstr = (*env)->GetStringUTFChars(env, logger_name, &iscopy);
	const char *class_name_cstr = (*env)->GetStringUTFChars(env, class_name, &iscopy);
	const char *method_name_cstr = (*env)->GetStringUTFChars(env, method_name, &iscopy);
	const char *file_name_cstr = (*env)->GetStringUTFChars(env, file_name, &iscopy);
	const char *thread_name_cstr = (*env)->GetStringUTFChars(env, thread_name, &iscopy);
	signed char *context_info_entries_array;
	signed char *context_info_strings_array;

	/*
	 * Write these to the TLS variables, so that the UST callbacks in
	 * lttng_ust_context.c can access them.
	 */
	context_info_entries_array = (*env)->GetByteArrayElements(env, context_info_entries, &iscopy);
	lttng_ust_context_info_tls.ctx_entries = (struct lttng_ust_jni_ctx_entry *) context_info_entries_array;
	lttng_ust_context_info_tls.ctx_entries_len = (*env)->GetArrayLength(env, context_info_entries);
	context_info_strings_array = (*env)->GetByteArrayElements(env, context_info_strings, &iscopy);
	lttng_ust_context_info_tls.ctx_strings = context_info_strings_array;
	lttng_ust_context_info_tls.ctx_strings_len = (*env)->GetArrayLength(env, context_info_strings);

	lttng_ust_tracepoint(lttng_log4j, event, msg_cstr, logger_name_cstr,
		   class_name_cstr, method_name_cstr, file_name_cstr,
		   line_number, timestamp, loglevel, thread_name_cstr);

	lttng_ust_context_info_tls.ctx_entries = NULL;
	lttng_ust_context_info_tls.ctx_entries_len = 0;
	lttng_ust_context_info_tls.ctx_strings = NULL;
	lttng_ust_context_info_tls.ctx_strings_len = 0;
	(*env)->ReleaseStringUTFChars(env, msg, msg_cstr);
	(*env)->ReleaseStringUTFChars(env, logger_name, logger_name_cstr);
	(*env)->ReleaseStringUTFChars(env, class_name, class_name_cstr);
	(*env)->ReleaseStringUTFChars(env, method_name, method_name_cstr);
	(*env)->ReleaseStringUTFChars(env, file_name, file_name_cstr);
	(*env)->ReleaseStringUTFChars(env, thread_name, thread_name_cstr);
	(*env)->ReleaseByteArrayElements(env, context_info_entries, context_info_entries_array, 0);
	(*env)->ReleaseByteArrayElements(env, context_info_strings, context_info_strings_array, 0);
}
