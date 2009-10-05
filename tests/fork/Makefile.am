INCLUDES = -I$(top_builddir)/share -I$(top_builddir)/libust \
	$(KCOMPAT_CFLAGS) $(URCU_CFLAGS)

noinst_PROGRAMS = fork fork2
fork_SOURCES = fork.c
fork_LDADD = $(top_builddir)/libust/libust.la $(URCU_LIBS)
fork2_SOURCES = fork2.c
fork2_LDADD = $(top_builddir)/libust/libust.la $(URCU_LIBS)

noinst_SCRIPTS = run
EXTRA_DIST = run
