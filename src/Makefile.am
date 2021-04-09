# SPDX-License-Identifier: LGPL-2.1-only

SUBDIRS = \
	common \
	libringbuffer \
	liblttng-ust-comm \
	libcounter \
	liblttng-ust \
	liblttng-ust-ctl \
	lib

if ENABLE_PYTHON_AGENT
SUBDIRS += python-lttngust
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = lttng-ust.pc lttng-ust-ctl.pc
