AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/tests/

noinst_PROGRAMS = libustctl_function_tests
libustctl_function_tests_SOURCES = libustctl_function_tests.c
libustctl_function_tests_LDADD = $(top_builddir)/libust/libust.la \
	$(top_builddir)/libustctl/libustctl.la \
	$(top_builddir)/libust-initializer.o \
	$(top_builddir)/tests/libtap.a \
	-lpthread

