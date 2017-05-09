AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include
AM_CFLAGS += -fno-strict-aliasing

lib_LTLIBRARIES = liblttng-ust-dl.la
liblttng_ust_dl_la_SOURCES = \
	lttng-ust-dl.c \
	ust_dl.c \
	ust_dl.h
liblttng_ust_dl_la_LIBADD = \
	$(top_builddir)/liblttng-ust/liblttng-ust.la

if LTTNG_UST_BUILD_WITH_LIBDL
liblttng_ust_dl_la_LIBADD += -ldl
endif
if LTTNG_UST_BUILD_WITH_LIBC_DL
liblttng_ust_dl_la_LIBADD += -lc
endif

liblttng_ust_dl_la_CFLAGS = -DUST_COMPONENT=liblttng-ust-dl $(AM_CFLAGS)
