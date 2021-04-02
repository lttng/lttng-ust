# SPDX-License-Identifier: LGPL-2.1-only

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = \
	include \
	src \
	tools \
	doc \
	tests

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
