AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/libust

noinst_PROGRAMS = register_test
register_test_SOURCES = register_test.c tp.h
register_test_LDADD = $(top_builddir)/libust/libust.la $(top_builddir)/libust-initializer.o
