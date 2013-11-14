AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include
AM_CFLAGS = -fno-strict-aliasing

lib_LTLIBRARIES = liblttng-ust-baddr.la
liblttng_ust_baddr_la_SOURCES = \
	lttng-ust-baddr.c \
	ust_baddr.c \
	ust_baddr.h \
	ust_baddr_statedump.c \
	ust_baddr_statedump.h
liblttng_ust_baddr_la_LIBADD = \
	-L$(top_builddir)/liblttng-ust/.libs \
	-llttng-ust

if LTTNG_UST_BUILD_WITH_LIBDL
liblttng_ust_baddr_la_LIBADD += -ldl
endif
if LTTNG_UST_BUILD_WITH_LIBC_DL
liblttng_ust_baddr_la_LIBADD += -lc
endif
