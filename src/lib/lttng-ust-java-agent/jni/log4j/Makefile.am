# SPDX-FileCopyrightText: 2023 EfficiOS, Inc
#
# SPDX-License-Identifier: LGPL-2.1-only

AM_CPPFLAGS += -I$(builddir) -I$(srcdir) $(JNI_CPPFLAGS)

lib_LTLIBRARIES = liblttng-ust-log4j-jni.la
liblttng_ust_log4j_jni_la_SOURCES = \
	lttng_ust_log4j2_tp.c \
	lttng_ust_log4j2_tp.h \
	lttng_ust_log4j_tp.c \
	lttng_ust_log4j_tp.h
nodist_liblttng_ust_log4j_jni_la_SOURCES =

if ENABLE_JAVA_AGENT_WITH_LOG4J
liblttng_ust_log4j_jni_la_SOURCES += lttng_ust_log4j.c
nodist_liblttng_ust_log4j_jni_la_SOURCES += org_lttng_ust_agent_log4j_LttngLog4jApi.h
endif

if ENABLE_JAVA_AGENT_WITH_LOG4J2
liblttng_ust_log4j_jni_la_SOURCES += lttng_ust_log4j2.c
nodist_liblttng_ust_log4j_jni_la_SOURCES += org_lttng_ust_agent_log4j2_LttngLog4j2Api.h
endif

liblttng_ust_log4j_jni_la_LIBADD = -lc \
	$(top_builddir)/src/lib/lttng-ust/liblttng-ust.la \
	$(top_builddir)/src/lib/lttng-ust-java-agent/jni/common/liblttng-ust-context-jni.la
