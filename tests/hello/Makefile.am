AM_CPPFLAGS = -I$(top_srcdir)/include

noinst_PROGRAMS = hello
hello_SOURCES = hello.c tp.c tp.h
hello_LDADD = $(top_builddir)/liblttng-ust/liblttng-ust.la

noinst_SCRIPTS = run
EXTRA_DIST = run
