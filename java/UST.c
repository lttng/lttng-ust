#include <jni.h>
#include <ust/marker.h>

JNIEXPORT void JNICALL Java_UST_ust_1java_1event (JNIEnv *env, jobject jobj, jstring ev_name, jstring args)
{
	jboolean iscopy;
	const char *ev_name_cstr = (*env)->GetStringUTFChars(env, ev_name, &iscopy);
	const char *args_cstr = (*env)->GetStringUTFChars(env, args, &iscopy);

	ust_marker(ust, java_event, "name %s args %s", ev_name_cstr, args_cstr);
}

UST_MARKER_LIB
