INCLUDES = -I$(top_builddir)/share -I$(top_builddir)/libust \
	$(KCOMPAT_CFLAGS) $(URCU_CFLAGS)

noinst_PROGRAMS = hello2
hello2_SOURCES = hello2.c
hello2_LDADD = $(top_builddir)/libust/libust.la $(URCU_LIBS)

noinst_SCRIPTS = run
EXTRA_DIST = run
