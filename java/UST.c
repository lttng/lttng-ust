#include <jni.h>

#define TRACEPOINT_CREATE_PROBES
#include "ust_java.h"

JNIEXPORT void JNICALL Java_UST_ust_1java_1event (JNIEnv *env, jobject jobj,
						jstring ev_name, jstring args)
{
	jboolean iscopy;
	const char *ev_name_cstr = (*env)->GetStringUTFChars(env, ev_name,
							&iscopy);
	const char *args_cstr = (*env)->GetStringUTFChars(env, args, &iscopy);

	tracepoint(ust_java_event, ev_name_cstr, args_cstr);
}

TRACEPOINT_LIB
