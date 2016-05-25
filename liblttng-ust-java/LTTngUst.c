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

#define _LGPL_SOURCE
#include "org_lttng_ust_LTTngUst.h"

#define TRACEPOINT_DEFINE
#define TRACEPOINT_CREATE_PROBES
#include "lttng_ust_java.h"

JNIEXPORT void JNICALL Java_org_lttng_ust_LTTngUst_tracepointInt(JNIEnv *env,
						jobject jobj,
						jstring ev_name,
						jint payload)
{
	jboolean iscopy;
	const char *ev_name_cstr = (*env)->GetStringUTFChars(env, ev_name, &iscopy);

	tracepoint(lttng_ust_java, int_event, ev_name_cstr, payload);

	(*env)->ReleaseStringUTFChars(env, ev_name, ev_name_cstr);
}

JNIEXPORT void JNICALL Java_org_lttng_ust_LTTngUst_tracepointIntInt(JNIEnv *env,
						jobject jobj,
						jstring ev_name,
						jint payload1,
						jint payload2)
{
	jboolean iscopy;
	const char *ev_name_cstr = (*env)->GetStringUTFChars(env, ev_name, &iscopy);

	tracepoint(lttng_ust_java, int_int_event, ev_name_cstr, payload1, payload2);

	(*env)->ReleaseStringUTFChars(env, ev_name, ev_name_cstr);
}

JNIEXPORT void JNICALL Java_org_lttng_ust_LTTngUst_tracepointLong(JNIEnv *env,
						jobject jobj,
						jstring ev_name,
						jlong payload)
{
	jboolean iscopy;
	const char *ev_name_cstr = (*env)->GetStringUTFChars(env, ev_name, &iscopy);

	tracepoint(lttng_ust_java, long_event, ev_name_cstr, payload);

	(*env)->ReleaseStringUTFChars(env, ev_name, ev_name_cstr);
}

JNIEXPORT void JNICALL Java_org_lttng_ust_LTTngUst_tracepointLongLong(JNIEnv *env,
						jobject jobj,
						jstring ev_name,
						jlong payload1,
						jlong payload2)
{
	jboolean iscopy;
	const char *ev_name_cstr = (*env)->GetStringUTFChars(env, ev_name, &iscopy);

	tracepoint(lttng_ust_java, long_long_event, ev_name_cstr, payload1, payload2);

	(*env)->ReleaseStringUTFChars(env, ev_name, ev_name_cstr);
}

JNIEXPORT void JNICALL Java_org_lttng_ust_LTTngUst_tracepointString(JNIEnv *env,
						jobject jobj,
						jstring ev_name,
						jstring payload)
{
	jboolean iscopy;
	const char *ev_name_cstr = (*env)->GetStringUTFChars(env, ev_name, &iscopy);
	const char *payload_cstr = (*env)->GetStringUTFChars(env, payload, &iscopy);

	tracepoint(lttng_ust_java, string_event, ev_name_cstr, payload_cstr);

	(*env)->ReleaseStringUTFChars(env, ev_name, ev_name_cstr);
	(*env)->ReleaseStringUTFChars(env, payload, payload_cstr);
}

