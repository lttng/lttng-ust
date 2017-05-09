AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include -Wsystem-headers

noinst_PROGRAMS = ctf-types
ctf_types_SOURCES = ctf-types.c tp.c ust_tests_ctf_types.h
ctf_types_LDADD = $(top_builddir)/liblttng-ust/liblttng-ust.la
ctf_types_CFLAGS = -Werror=old-style-definition $(AM_CFLAGS)

if LTTNG_UST_BUILD_WITH_LIBDL
ctf_types_LDADD += -ldl
endif
if LTTNG_UST_BUILD_WITH_LIBC_DL
ctf_types_LDADD += -lc
endif
