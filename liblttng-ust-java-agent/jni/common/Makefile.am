AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include $(JNI_CPPFLAGS)

lib_LTLIBRARIES = liblttng-ust-context-jni.la
liblttng_ust_context_jni_la_SOURCES = lttng_ust_context.c lttng_ust_context.h

nodist_liblttng_ust_context_jni_la_SOURCES = org_lttng_ust_agent_context_LttngContextApi.h

liblttng_ust_context_jni_la_LIBADD = -lc -L$(top_builddir)/liblttng-ust/.libs -llttng-ust
