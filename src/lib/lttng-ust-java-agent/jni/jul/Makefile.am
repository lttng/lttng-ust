# SPDX-FileCopyrightText: 2023 EfficiOS, Inc
#
# SPDX-License-Identifier: LGPL-2.1-only

AM_CPPFLAGS += -I$(builddir) -I$(srcdir) $(JNI_CPPFLAGS)

lib_LTLIBRARIES = liblttng-ust-jul-jni.la
liblttng_ust_jul_jni_la_SOURCES = lttng_ust_jul.c \
	lttng_ust_jul.h

nodist_liblttng_ust_jul_jni_la_SOURCES = org_lttng_ust_agent_jul_LttngJulApi.h

liblttng_ust_jul_jni_la_LIBADD = -lc \
	$(top_builddir)/src/lib/lttng-ust/liblttng-ust.la \
	$(top_builddir)/src/lib/lttng-ust-java-agent/jni/common/liblttng-ust-context-jni.la
