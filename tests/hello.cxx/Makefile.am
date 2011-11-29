AM_CPPFLAGS = -I$(top_srcdir)/include

noinst_PROGRAMS = hello
hello_SOURCES = hello.cpp tp.c ust_tests_hello.h
hello_LDADD = $(top_builddir)/liblttng-ust/liblttng-ust.la

noinst_SCRIPTS = run
EXTRA_DIST = run
