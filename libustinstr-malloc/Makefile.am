AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = -fno-strict-aliasing

lib_LTLIBRARIES = libustinstr-malloc.la
libustinstr_malloc_la_SOURCES = mallocwrap.c
libustinstr_malloc_la_LIBADD = -ldl

noinst_SCRIPTS = run
EXTRA_DIST = run
