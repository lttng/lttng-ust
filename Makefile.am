# SPDX-FileCopyrightText: 2023 EfficiOS, Inc
#
# SPDX-License-Identifier: LGPL-2.1-only

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = \
	include \
	src \
	tools \
	doc \
	tests \
	extras

dist_doc_DATA = \
	ChangeLog \
	LICENSE \
	README.md

dist_noinst_DATA = \
	.reuse/dep5 \
	CodingStyle.md \
	CONTRIBUTING.md \
	LICENSES/Autoconf-exception-2.0.txt \
	LICENSES/BSD-2-Clause.txt \
	LICENSES/BSD-3-Clause.txt \
	LICENSES/CC-BY-4.0.txt \
	LICENSES/FSFAP.txt \
	LICENSES/GPL-2.0-only.txt \
	LICENSES/GPL-2.0-or-later.txt \
	LICENSES/GPL-3.0-or-later.txt \
	LICENSES/LGPL-2.1-only.txt \
	LICENSES/LGPL-2.1-or-later.txt \
	LICENSES/LicenseRef-Autoconf-exception-macro.txt \
	LICENSES/MIT.txt

check-loop:
	cd tests && $(MAKE) $(AM_MAKEFLAGS) check-loop
.PHONY: check-loop
