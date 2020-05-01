# SPDX-License-Identifier: LGPL-2.1-only

dist_bin_SCRIPTS = lttng-gen-tp

all-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(dist_bin_SCRIPTS); do \
			cp -f $(srcdir)/$$script $(builddir); \
		done; \
	fi

clean-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(dist_bin_SCRIPTS); do \
			rm -f $(builddir)/$$script; \
		done; \
	fi
