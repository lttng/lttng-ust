AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include -Wsystem-headers

noinst_PROGRAMS = daemon
daemon_SOURCES = daemon.c ust_tests_daemon.h
daemon_LDADD = $(top_builddir)/liblttng-ust/liblttng-ust.la \
		$(top_builddir)/liblttng-ust-fork/liblttng-ust-fork.la

if LTTNG_UST_BUILD_WITH_LIBDL
daemon_LDADD += -ldl
endif
if LTTNG_UST_BUILD_WITH_LIBC_DL
daemon_LDADD += -lc
endif

noinst_SCRIPTS = run
EXTRA_DIST = run
