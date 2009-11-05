AM_CPPFLAGS = -I$(top_srcdir)/include

noinst_PROGRAMS = hello
hello_SOURCES = hello.c tp.c tp.h
hello_LDADD = $(top_builddir)/libust/libust.la $(top_builddir)/libust-initializer.o

noinst_SCRIPTS = run
EXTRA_DIST = run
