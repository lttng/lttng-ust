AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include -Wsystem-headers

noinst_PROGRAMS = ust-variant
ust_variant_SOURCES = ust-variant.c
ust_variant_LDADD = $(top_builddir)/liblttng-ust/liblttng-ust.la
ust_variant_CFLAGS = -Werror=old-style-definition $(AM_CFLAGS)

if LTTNG_UST_BUILD_WITH_LIBDL
ust_variant_LDADD += -ldl
endif
if LTTNG_UST_BUILD_WITH_LIBC_DL
ust_variant_LDADD += -lc
endif
