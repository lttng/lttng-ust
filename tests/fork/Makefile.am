INCLUDES = -I$(top_builddir)/share -I$(top_builddir)/libust \
	$(KCOMPAT_CFLAGS) $(URCU_CFLAGS)

noinst_PROGRAMS = fork
fork_SOURCES = fork.c
fork_LDADD = $(top_builddir)/libust/libust.la $(URCU_LIBS)

noinst_SCRIPTS = run
EXTRA_DIST = run
