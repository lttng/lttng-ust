AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include
AM_CFLAGS += -fno-strict-aliasing

lib_LTLIBRARIES = liblttng-ust-libc-wrapper.la \
  liblttng-ust-pthread-wrapper.la

liblttng_ust_libc_wrapper_la_SOURCES = \
	lttng-ust-malloc.c \
	ust_libc.h

liblttng_ust_libc_wrapper_la_LIBADD = \
	-L$(top_builddir)/liblttng-ust/.libs \
	-llttng-ust \
	$(DL_LIBS)

liblttng_ust_pthread_wrapper_la_SOURCES = \
	lttng-ust-pthread.c \
	ust_pthread.h

liblttng_ust_pthread_wrapper_la_LIBADD = \
	-L$(top_builddir)/liblttng-ust/.libs \
	-llttng-ust \
	$(DL_LIBS)

dist_noinst_SCRIPTS = run
EXTRA_DIST = README
