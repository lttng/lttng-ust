AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/tests/utils

noinst_PROGRAMS = prog
prog_SOURCES = prog.c
prog_LDADD = $(top_builddir)/snprintf/libustsnprintf.la \
	$(top_builddir)/tests/utils/libtap.a

dist_noinst_SCRIPTS = test_snprintf
