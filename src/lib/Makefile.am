# SPDX-FileCopyrightText: 2023 EfficiOS, Inc
#
# SPDX-License-Identifier: LGPL-2.1-only

SUBDIRS = \
	lttng-ust-common \
	lttng-ust-tracepoint \
	lttng-ust \
	lttng-ust-ctl \
	lttng-ust-fd \
	lttng-ust-fork \
	lttng-ust-cyg-profile \
	lttng-ust-libc-wrapper \
	lttng-ust-pthread-wrapper

if ENABLE_UST_DL
SUBDIRS += lttng-ust-dl
endif

if ENABLE_JNI_INTERFACE
SUBDIRS += lttng-ust-java
endif

if ENABLE_JAVA_AGENT
SUBDIRS += lttng-ust-java-agent
endif

if ENABLE_PYTHON_AGENT
SUBDIRS += lttng-ust-python-agent
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = lttng-ust.pc lttng-ust-ctl.pc
