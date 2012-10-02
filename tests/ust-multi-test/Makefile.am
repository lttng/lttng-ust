AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include -I$(top_srcdir)/libust

noinst_PROGRAMS = ust-multi-test
ust_multi_test_SOURCES = ust-multi-test.c
ust_multi_test_LDADD = $(top_builddir)/liblttng-ust-comm/liblttng-ust-comm.la \
	$(top_builddir)/libringbuffer/libringbuffer.la \
	$(top_builddir)/snprintf/libustsnprintf.la
