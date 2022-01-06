AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include $(JNI_CPPFLAGS)

lib_LTLIBRARIES = liblttng-ust-log4j-jni.la
liblttng_ust_log4j_jni_la_SOURCES = \
	lttng_ust_log4j_tp.c \
	lttng_ust_log4j_tp.h
nodist_liblttng_ust_log4j_jni_la_SOURCES =

if BUILD_JAVA_AGENT_WITH_LOG4J
liblttng_ust_log4j_jni_la_SOURCES += lttng_ust_log4j.c
nodist_liblttng_ust_log4j_jni_la_SOURCES += org_lttng_ust_agent_log4j_LttngLog4jApi.h
endif

if BUILD_JAVA_AGENT_WITH_LOG4J2
liblttng_ust_log4j_jni_la_SOURCES += lttng_ust_log4j2.c
nodist_liblttng_ust_log4j_jni_la_SOURCES += org_lttng_ust_agent_log4j2_LttngLog4j2Api.h
endif

liblttng_ust_log4j_jni_la_LIBADD = -lc \
	-L$(top_builddir)/liblttng-ust/.libs \
	-L$(top_builddir)/liblttng-ust-java-agent/jni/common/.libs \
	-llttng-ust-context-jni \
	-llttng-ust
