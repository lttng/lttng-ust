/*
 * Copyright (C) 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include "org_lttng_ust_agent_log4j_LttngLogAppender.h"

#define TRACEPOINT_DEFINE
#define TRACEPOINT_CREATE_PROBES
#include "lttng_ust_log4j.h"

/*
 * System tracepoint meaning only root agent will fire this.
 */
JNIEXPORT void JNICALL Java_org_lttng_ust_agent_log4j_LttngLogAppender_tracepoint(JNIEnv *env,
						jobject jobj,
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

	tracepoint(lttng_log4j, event, msg_cstr, logger_name_cstr,
		   class_name_cstr, method_name_cstr, file_name_cstr,
		   line_number, timestamp, loglevel, thread_name_cstr);

	(*env)->ReleaseStringUTFChars(env, msg, msg_cstr);
	(*env)->ReleaseStringUTFChars(env, logger_name, logger_name_cstr);
	(*env)->ReleaseStringUTFChars(env, class_name, class_name_cstr);
	(*env)->ReleaseStringUTFChars(env, method_name, method_name_cstr);
	(*env)->ReleaseStringUTFChars(env, file_name, file_name_cstr);
	(*env)->ReleaseStringUTFChars(env, thread_name, thread_name_cstr);
}

