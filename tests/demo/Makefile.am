# -Wsystem-headers is needed to print warnings in the tracepoint
# description file.
AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include -Wsystem-headers

# Set LIBS to nothing so the application does not link on useless
# libraries.
LIBS =

# Force the shared flag on the noinst libraries since they are
# only built static by default
FORCE_SHARED_LIB_OPTIONS = -module -shared -avoid-version \
			   -rpath $(abs_builddir)

noinst_LTLIBRARIES = liblttng-ust-provider-ust-tests-demo.la \
	liblttng-ust-provider-ust-tests-demo3.la

#contains ust_tests_demo.h and ust_tests_demo2.h provider probes
liblttng_ust_provider_ust_tests_demo_la_SOURCES = \
	tp.c ust_tests_demo.h \
	tp2.c ust_tests_demo2.h
liblttng_ust_provider_ust_tests_demo_la_LIBADD = \
	$(top_builddir)/liblttng-ust/liblttng-ust.la
liblttng_ust_provider_ust_tests_demo_la_LDFLAGS = \
	$(FORCE_SHARED_LIB_OPTIONS)

#contains ust_tests_demo3.h provider probes
liblttng_ust_provider_ust_tests_demo3_la_SOURCES = \
	tp3.c ust_tests_demo3.h
liblttng_ust_provider_ust_tests_demo3_la_LIBADD = \
	$(top_builddir)/liblttng-ust/liblttng-ust.la
liblttng_ust_provider_ust_tests_demo3_la_LDFLAGS = \
	$(FORCE_SHARED_LIB_OPTIONS)

noinst_PROGRAMS = demo
demo_SOURCES = demo.c ust_tests_demo.h
# The demo program only depends on libdl/libc for dlopen().
if LTTNG_UST_BUILD_WITH_LIBDL
demo_LDADD = -ldl
endif
if LTTNG_UST_BUILD_WITH_LIBC_DL
demo_LDADD = -lc
endif

