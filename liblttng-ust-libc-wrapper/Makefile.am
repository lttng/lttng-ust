AM_CFLAGS += -I$(srcdir) -fno-strict-aliasing

lib_LTLIBRARIES = liblttng-ust-libc-wrapper.la \
  liblttng-ust-pthread-wrapper.la

liblttng_ust_libc_wrapper_la_SOURCES = \
	lttng-ust-malloc.c \
	ust_libc.h

liblttng_ust_libc_wrapper_la_LIBADD = \
	$(top_builddir)/liblttng-ust/liblttng-ust.la \
	$(DL_LIBS)

liblttng_ust_pthread_wrapper_la_SOURCES = \
	lttng-ust-pthread.c \
	ust_pthread.h

liblttng_ust_pthread_wrapper_la_LIBADD = \
	$(top_builddir)/liblttng-ust/liblttng-ust.la \
	$(DL_LIBS)

dist_noinst_SCRIPTS = run
EXTRA_DIST = README
