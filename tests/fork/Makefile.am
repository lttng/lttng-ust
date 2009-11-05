AM_CPPFLAGS = -I$(top_srcdir)/include

noinst_PROGRAMS = fork fork2
fork_SOURCES = fork.c
fork_LDADD = $(top_builddir)/libust/libust.la $(top_builddir)/libust-initializer.o
fork2_SOURCES = fork2.c
fork2_LDADD = $(top_builddir)/libust/libust.la $(top_builddir)/libust-initializer.o

noinst_SCRIPTS = run
EXTRA_DIST = run
