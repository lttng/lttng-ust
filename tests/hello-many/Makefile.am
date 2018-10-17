AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include -Wsystem-headers

noinst_PROGRAMS = hello-many
hello_many_SOURCES = hello-many.c tp.c ust_tests_hello_many.h
hello_many_LDADD = $(top_builddir)/liblttng-ust/liblttng-ust.la
hello_many_CFLAGS = -Werror=old-style-definition $(AM_CFLAGS)

if LTTNG_UST_BUILD_WITH_LIBDL
hello_many_LDADD += -ldl
endif
if LTTNG_UST_BUILD_WITH_LIBC_DL
hello_many_LDADD += -lc
endif
