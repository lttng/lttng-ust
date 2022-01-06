/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2016-2022 EfficiOS Inc.
 * Copyright (C) 2016 Alexandre Montplaisir <alexmonthy@efficios.com>
 * Copyright (C) 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#define _LGPL_SOURCE
#include "org_lttng_ust_agent_log4j2_LttngLog4j2Api.h"
#include "lttng_ust_log4j_tp.h"
#include "../common/lttng_ust_context.h"

/*
 * Those are an exact map from the class org.apache.log4j.Level.
 */
enum loglevel_log4j1 {
        LOGLEVEL_LOG4J1_OFF              = INT32_MAX,
        LOGLEVEL_LOG4J1_FATAL            = 50000,
        LOGLEVEL_LOG4J1_ERROR            = 40000,
        LOGLEVEL_LOG4J1_WARN             = 30000,
        LOGLEVEL_LOG4J1_INFO             = 20000,
        LOGLEVEL_LOG4J1_DEBUG            = 10000,
        LOGLEVEL_LOG4J1_TRACE            = 5000,
        LOGLEVEL_LOG4J1_ALL              = INT32_MIN,
};

/*
 * Those are an exact map from the class
 * org.apache.logging.log4j.spi.StandardLevel.
 */
enum loglevel_log4j2 {
        LOGLEVEL_LOG4J2_OFF              = 0,
        LOGLEVEL_LOG4J2_FATAL            = 100,
        LOGLEVEL_LOG4J2_ERROR            = 200,
        LOGLEVEL_LOG4J2_WARN             = 300,
        LOGLEVEL_LOG4J2_INFO             = 400,
        LOGLEVEL_LOG4J2_DEBUG            = 500,
        LOGLEVEL_LOG4J2_TRACE            = 600,
        LOGLEVEL_LOG4J2_ALL              = INT32_MAX,
};

/*
 * The integer values of the loglevels has obviously changed in log4j2,
 * translate them to the values of log4j1 since they are exposed in the API of
 * lttng-tools.
 *
 * Custom loglevels might pose a problem when using ranges.
 */
static jint loglevel_2x_to_1x(jint loglevel)
{
	switch (loglevel) {
	case LOGLEVEL_LOG4J2_OFF:
		return LOGLEVEL_LOG4J1_OFF;
	case LOGLEVEL_LOG4J2_FATAL:
		return LOGLEVEL_LOG4J1_FATAL;
	case LOGLEVEL_LOG4J2_ERROR:
		return LOGLEVEL_LOG4J1_ERROR;
	case LOGLEVEL_LOG4J2_WARN:
		return LOGLEVEL_LOG4J1_WARN;
	case LOGLEVEL_LOG4J2_INFO:
		return LOGLEVEL_LOG4J1_INFO;
	case LOGLEVEL_LOG4J2_DEBUG:
		return LOGLEVEL_LOG4J1_DEBUG;
	case LOGLEVEL_LOG4J2_TRACE:
		return LOGLEVEL_LOG4J1_TRACE;
	case LOGLEVEL_LOG4J2_ALL:
		return LOGLEVEL_LOG4J1_ALL;
	default:
		/* Handle custom loglevels. */
		return loglevel;
	}
}

/*
 * Tracepoint used by Java applications using the log4j 2.x handler.
 */
JNIEXPORT void JNICALL Java_org_lttng_ust_agent_log4j2_LttngLog4j2Api_tracepointWithContext(JNIEnv *env,
						jobject jobj __attribute__((unused)),
						jstring message,
						jstring loggerName,
						jstring className,
						jstring methodName,
						jstring fileName,
						jint lineNumber,
						jlong timeStamp,
						jint logLevel,
						jstring threadName,
						jbyteArray context_info_entries,
						jbyteArray context_info_strings)
{
	jboolean iscopy;
	const char *msg_cstr = (*env)->GetStringUTFChars(env, message, &iscopy);
	const char *logger_name_cstr = (*env)->GetStringUTFChars(env, loggerName, &iscopy);
	const char *class_name_cstr = (*env)->GetStringUTFChars(env, className, &iscopy);
	const char *method_name_cstr = (*env)->GetStringUTFChars(env, methodName, &iscopy);
	const char *file_name_cstr = (*env)->GetStringUTFChars(env, fileName, &iscopy);
	const char *thread_name_cstr = (*env)->GetStringUTFChars(env, threadName, &iscopy);
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

	tracepoint(lttng_log4j, event, msg_cstr, logger_name_cstr,
		   class_name_cstr, method_name_cstr, file_name_cstr,
		   lineNumber, timeStamp, loglevel_2x_to_1x(logLevel), thread_name_cstr);

	lttng_ust_context_info_tls.ctx_entries = NULL;
	lttng_ust_context_info_tls.ctx_entries_len = 0;
	lttng_ust_context_info_tls.ctx_strings = NULL;
	lttng_ust_context_info_tls.ctx_strings_len = 0;
	(*env)->ReleaseStringUTFChars(env, message, msg_cstr);
	(*env)->ReleaseStringUTFChars(env, loggerName, logger_name_cstr);
	(*env)->ReleaseStringUTFChars(env, className, class_name_cstr);
	(*env)->ReleaseStringUTFChars(env, methodName, method_name_cstr);
	(*env)->ReleaseStringUTFChars(env, fileName, file_name_cstr);
	(*env)->ReleaseStringUTFChars(env, threadName, thread_name_cstr);
	(*env)->ReleaseByteArrayElements(env, context_info_entries, context_info_entries_array, 0);
	(*env)->ReleaseByteArrayElements(env, context_info_strings, context_info_strings_array, 0);
}
