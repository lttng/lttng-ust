# SPDX-License-Identifier: LGPL-2.1-only

AM_CPPFLAGS += -I$(builddir) -I$(srcdir) $(JNI_CPPFLAGS)

lib_LTLIBRARIES = liblttng-ust-log4j-jni.la
liblttng_ust_log4j_jni_la_SOURCES = lttng_ust_log4j.c \
	lttng_ust_log4j.h

nodist_liblttng_ust_log4j_jni_la_SOURCES = org_lttng_ust_agent_log4j_LttngLog4jApi.h

liblttng_ust_log4j_jni_la_LIBADD = -lc \
	$(top_builddir)/src/lib/lttng-ust/liblttng-ust.la \
	$(top_builddir)/src/lib/lttng-ust-java-agent/jni/common/liblttng-ust-context-jni.la
