AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/tests/

noinst_PROGRAMS = prog
prog_SOURCES = prog.c
prog_LDADD = $(top_builddir)/snprintf/libustsnprintf.la \
	$(top_builddir)/tests/libtap.a

noinst_SCRIPT = test_snprintf
EXTRA_DIST = test_snprintf
