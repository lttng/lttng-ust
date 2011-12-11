# -Wsystem-headers is needed to print warnings in the tracepoint
# description file.
AM_CPPFLAGS = -I$(top_srcdir)/include -Wsystem-headers

# We install the plugins into the /tmp/lttng-ust-divert directory to
# please libtool, which absolutely needs a target install location. We
# don't want to pollute the system with test program plugins.
# We use the .so in .libs/ for the tests.
noinst_plugins_libdir = "/tmp/lttng-ust-divert"

noinst_plugins_lib_LTLIBRARIES = liblttng-ust-provider-ust-tests-demo.la \
	liblttng-ust-provider-ust-tests-demo3.la

#contains ust_tests_demo.h and ust_tests_demo2.h provider probes
liblttng_ust_provider_ust_tests_demo_la_SOURCES = \
	tp.c ust_tests_demo.h \
	tp2.c ust_tests_demo2.h
liblttng_ust_provider_ust_tests_demo_la_LIBADD = \
	$(top_builddir)/liblttng-ust/liblttng-ust.la

#contains ust_tests_demo3.h provider probes
liblttng_ust_provider_ust_tests_demo3_la_SOURCES = \
	tp3.c ust_tests_demo3.h
liblttng_ust_provider_ust_tests_demo3_la_LIBADD = \
	$(top_builddir)/liblttng-ust/liblttng-ust.la

noinst_PROGRAMS = demo
demo_SOURCES = demo.c ust_tests_demo.h
# The demo program only depends on libdl.
demo_LIBS = -ldl
