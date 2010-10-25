AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/tests/

noinst_PROGRAMS = ustcmd_function_tests
ustcmd_function_tests_SOURCES = ustcmd_function_tests.c
ustcmd_function_tests_LDADD = $(top_builddir)/libust/libust.la \
	$(top_builddir)/libustcmd/libustcmd.la \
	$(top_builddir)/libust-initializer.o \
	$(top_builddir)/tests/libtap.la \
	-lpthread

