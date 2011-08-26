AM_CPPFLAGS = -I$(top_srcdir)/include

noinst_PROGRAMS = fork fork2
fork_SOURCES = fork.c ust_tests_fork.h
fork_LDADD = $(top_builddir)/libust/libust.la
fork2_SOURCES = fork2.c
fork2_LDADD = $(top_builddir)/libust/libust.la

noinst_SCRIPTS = run
EXTRA_DIST = run
