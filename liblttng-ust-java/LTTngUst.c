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

#include <jni.h>

#define TRACEPOINT_DEFINE
#define TRACEPOINT_CREATE_PROBES
#include "lttng_ust_java.h"

JNIEXPORT void JNICALL Java_org_lttng_ust_LTTngUst_tracepointString(JNIEnv *env,
						jobject jobj,
						jstring ev_name,
						jstring args)
{
	jboolean iscopy;
	const char *ev_name_cstr = (*env)->GetStringUTFChars(env, ev_name,
							&iscopy);
	const char *args_cstr = (*env)->GetStringUTFChars(env, args, &iscopy);

	tracepoint(lttng_ust_java, string, ev_name_cstr, args_cstr);

	(*env)->ReleaseStringUTFChars(env, ev_name, ev_name_cstr);
	(*env)->ReleaseStringUTFChars(env, args, args_cstr);
}
