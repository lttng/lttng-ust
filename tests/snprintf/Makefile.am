AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/tests/utils

noinst_PROGRAMS = test_snprintf
test_snprintf_SOURCES = snprintf.c
test_snprintf_LDADD = $(top_builddir)/snprintf/libustsnprintf.la \
	$(top_builddir)/tests/utils/libtap.a

EXTRA_DIST = README
