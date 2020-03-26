AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include $(JNI_CPPFLAGS)

lib_LTLIBRARIES = liblttng-ust-jul-jni.la
liblttng_ust_jul_jni_la_SOURCES = lttng_ust_jul.c \
	lttng_ust_jul.h

nodist_liblttng_ust_jul_jni_la_SOURCES = org_lttng_ust_agent_jul_LttngJulApi.h

liblttng_ust_jul_jni_la_LIBADD = -lc \
	$(top_builddir)/liblttng-ust/liblttng-ust.la \
	$(top_builddir)/liblttng-ust-java-agent/jni/common/liblttng-ust-context-jni.la
