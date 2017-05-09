AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include
AM_CFLAGS += -fno-strict-aliasing

lib_LTLIBRARIES = liblttng-ust-fd.la
liblttng_ust_fd_la_SOURCES = \
	lttng-ust-fd.c
liblttng_ust_fd_la_LIBADD = \
	$(top_builddir)/liblttng-ust-comm/liblttng-ust-comm.la

if LTTNG_UST_BUILD_WITH_LIBDL
liblttng_ust_fd_la_LIBADD += -ldl
endif
if LTTNG_UST_BUILD_WITH_LIBC_DL
liblttng_ust_fd_la_LIBADD += -lc
endif

liblttng_ust_fd_la_CFLAGS = -DUST_COMPONENT=liblttng-ust-fd $(AM_CFLAGS)
