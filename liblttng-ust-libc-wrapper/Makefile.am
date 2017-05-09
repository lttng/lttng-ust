AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include
AM_CFLAGS += -fno-strict-aliasing

lib_LTLIBRARIES = liblttng-ust-libc-wrapper.la \
  liblttng-ust-pthread-wrapper.la
liblttng_ust_libc_wrapper_la_SOURCES = \
	lttng-ust-malloc.c \
	ust_libc.h
liblttng_ust_libc_wrapper_la_LIBADD = \
	-L$(top_builddir)/liblttng-ust/.libs \
	-llttng-ust

liblttng_ust_pthread_wrapper_la_SOURCES = \
	lttng-ust-pthread.c \
	ust_pthread.h
liblttng_ust_pthread_wrapper_la_LIBADD = \
	-L$(top_builddir)/liblttng-ust/.libs \
	-llttng-ust

if LTTNG_UST_BUILD_WITH_LIBDL
liblttng_ust_libc_wrapper_la_LIBADD += -ldl
liblttng_ust_pthread_wrapper_la_LIBADD += -ldl
endif
if LTTNG_UST_BUILD_WITH_LIBC_DL
liblttng_ust_libc_wrapper_la_LIBADD += -lc
liblttng_ust_pthread_wrapper_la_LIBADD += -lc
endif

noinst_SCRIPTS = run
EXTRA_DIST = run
