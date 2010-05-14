AM_CPPFLAGS = -I$(top_srcdir)/include

noinst_PROGRAMS = dlopen
noinst_LTLIBRARIES = libdummy.la
libdummy_la_SOURCES = libdummy.c
libdummy_la_LIBADD = $(top_builddir)/libust/libust.la $(top_builddir)/libust-initializer.o
libdummy_la_LDFLAGS = -rpath /nowhere
dlopen_SOURCES = dlopen.c
dlopen_LDADD = -ldl $(top_builddir)/libust/libust.la $(top_builddir)/libust-initializer.o

noinst_SCRIPTS = run
EXTRA_DIST = run
