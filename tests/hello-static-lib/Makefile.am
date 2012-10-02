AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include -Wsystem-headers

noinst_LTLIBRARIES = liblttng-ust-provider-ust-test-hello.la
liblttng_ust_provider_ust_test_hello_la_SOURCES = \
	tp.c ust_tests_hello.h
liblttng_ust_provider_ust_test_hello_la_LIBADD = \
	$(top_builddir)/liblttng-ust/liblttng-ust.la

noinst_PROGRAMS = hello
hello_SOURCES = hello.c
hello_LDADD = -ldl liblttng-ust-provider-ust-test-hello.la

noinst_SCRIPTS = run
EXTRA_DIST = run
