AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/tests/utils

noinst_PROGRAMS = prog
prog_SOURCES = prog.c
prog_LDADD = $(top_builddir)/snprintf/libustsnprintf.la \
	$(top_builddir)/tests/utils/libtap.a

SCRIPT_LIST = test_snprintf

dist_noinst_SCRIPTS = $(SCRIPT_LIST)

all-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(SCRIPT_LIST); do \
			cp -f $(srcdir)/$$script $(builddir); \
		done; \
	fi

clean-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(SCRIPT_LIST); do \
			rm -f $(builddir)/$$script; \
		done; \
	fi
