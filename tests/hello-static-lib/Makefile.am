AM_CPPFLAGS = -I$(top_srcdir)/include -Wsystem-headers

noinst_LTLIBRARIES = liblttng-ust-provider-ust-test-hello.la
liblttng_ust_provider_ust_test_hello_la_SOURCES = \
	tp.c ust_tests_hello.h

noinst_PROGRAMS = hello
hello_SOURCES = hello.c
hello_LDADD = $(top_builddir)/liblttng-ust/liblttng-ust.la \
	liblttng-ust-provider-ust-test-hello.la

noinst_SCRIPTS = run
EXTRA_DIST = run
