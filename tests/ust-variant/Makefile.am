AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include -Wsystem-headers

noinst_PROGRAMS = ust-variant
ust_variant_SOURCES = ust-variant.c
ust_variant_LDADD = $(top_builddir)/liblttng-ust/liblttng-ust.la $(DL_LIBS)
ust_variant_CFLAGS = -Werror=old-style-definition $(AM_CFLAGS)
