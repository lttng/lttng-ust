AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS += -fno-strict-aliasing

lib_LTLIBRARIES = liblttng-ust-fork.la
liblttng_ust_fork_la_SOURCES = ustfork.c
liblttng_ust_fork_la_LIBADD = \
	$(top_builddir)/liblttng-ust/liblttng-ust.la \
	$(DL_LIBS)

liblttng_ust_fork_la_CFLAGS = -DUST_COMPONENT=liblttng-ust-fork $(AM_CFLAGS)
