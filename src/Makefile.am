# SPDX-License-Identifier: LGPL-2.1-only

SUBDIRS = \
	common \
	lib

if ENABLE_PYTHON_AGENT
SUBDIRS += python-lttngust
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = lttng-ust.pc lttng-ust-ctl.pc
