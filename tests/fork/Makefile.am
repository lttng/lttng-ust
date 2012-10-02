AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include -Wsystem-headers

noinst_PROGRAMS = fork fork2
fork_SOURCES = fork.c ust_tests_fork.h
fork_LDADD = $(top_builddir)/liblttng-ust/liblttng-ust.la \
		$(top_builddir)/liblttng-ust-fork/liblttng-ust-fork.la
fork2_SOURCES = fork2.c
fork2_LDADD = $(top_builddir)/liblttng-ust/liblttng-ust.la \
		$(top_builddir)/liblttng-ust-fork/liblttng-ust-fork.la

noinst_SCRIPTS = run
EXTRA_DIST = run
