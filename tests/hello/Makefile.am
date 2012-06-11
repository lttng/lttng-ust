AM_CPPFLAGS = -I$(top_srcdir)/include -Wsystem-headers

noinst_PROGRAMS = hello
hello_SOURCES = hello.c tp.c ust_tests_hello.h
hello_LDADD = $(top_builddir)/liblttng-ust/liblttng-ust.la

noinst_SCRIPTS = run
EXTRA_DIST = run
