AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = -fno-strict-aliasing

lib_LTLIBRARIES = liblttng-ust-malloc.la
liblttng_ust_malloc_la_SOURCES = mallocwrap.c
liblttng_ust_malloc_la_LIBADD = -ldl

noinst_SCRIPTS = run
EXTRA_DIST = run
