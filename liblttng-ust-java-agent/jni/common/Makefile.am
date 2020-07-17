AM_CPPFLAGS += -I$(builddir) -I$(srcdir) $(JNI_CPPFLAGS)

lib_LTLIBRARIES = liblttng-ust-context-jni.la
liblttng_ust_context_jni_la_SOURCES = lttng_ust_context.c lttng_ust_context.h

nodist_liblttng_ust_context_jni_la_SOURCES = org_lttng_ust_agent_context_LttngContextApi.h

liblttng_ust_context_jni_la_LIBADD = -lc \
	$(top_builddir)/liblttng-ust/liblttng-ust.la
