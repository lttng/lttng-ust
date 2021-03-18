# SPDX-License-Identifier: LGPL-2.1-only

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = . include snprintf libringbuffer liblttng-ust-comm \
		libcounter \
		libmsgpack \
		liblttng-ust \
		liblttng-ust-ctl \
		liblttng-ust-fd \
		liblttng-ust-fork \
		liblttng-ust-libc-wrapper \
		liblttng-ust-cyg-profile \
		tools

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
SUBDIRS += python-lttngust \
		liblttng-ust-python-agent
endif

SUBDIRS += tests doc

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = lttng-ust.pc lttng-ust-ctl.pc

dist_doc_DATA = \
	ChangeLog \
	LICENSE \
	README.md

dist_noinst_DATA = \
	CodingStyle \
	CONTRIBUTING.md \
	LICENSES/BSD-2-Clause \
	LICENSES/BSD-3-Clause \
	LICENSES/GPL-2.0 \
	LICENSES/GPL-3.0 \
	LICENSES/LGPL-2.1 \
	LICENSES/MIT

check-loop:
	cd tests && $(MAKE) $(AM_MAKEFLAGS) check-loop
.PHONY: check-loop
