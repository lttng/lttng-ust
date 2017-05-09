AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS += -fno-strict-aliasing

lib_LTLIBRARIES = liblttng-ust-fork.la
liblttng_ust_fork_la_SOURCES = ustfork.c
liblttng_ust_fork_la_LIBADD = \
	$(top_builddir)/liblttng-ust/liblttng-ust.la

if LTTNG_UST_BUILD_WITH_LIBDL
liblttng_ust_fork_la_LIBADD += -ldl
endif
if LTTNG_UST_BUILD_WITH_LIBC_DL
liblttng_ust_fork_la_LIBADD += -lc
endif

liblttng_ust_fork_la_CFLAGS = -DUST_COMPONENT=liblttng-ust-fork $(AM_CFLAGS)
