# SPDX-License-Identifier: LGPL-2.1-only

SUBDIRS = \
	common \
	libringbuffer \
	liblttng-ust-comm \
	libcounter \
	libmsgpack \
	liblttng-ust \
	liblttng-ust-ctl \
	liblttng-ust-fd \
	liblttng-ust-fork \
	liblttng-ust-libc-wrapper \
	liblttng-ust-cyg-profile

if ENABLE_UST_DL
SUBDIRS += liblttng-ust-dl
endif

if ENABLE_JNI_INTERFACE
SUBDIRS += liblttng-ust-java
endif

if ENABLE_JAVA_AGENT
SUBDIRS += liblttng-ust-java-agent
endif

if ENABLE_PYTHON_AGENT
SUBDIRS += \
	python-lttngust \
	liblttng-ust-python-agent
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = lttng-ust.pc lttng-ust-ctl.pc
